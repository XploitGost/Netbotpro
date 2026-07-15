from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from core.privacy_redaction import redact_sensitive_data, redact_sensitive_text

DEFAULT_REGISTRY_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "service_fingerprints.json"
)
DEFAULT_DNS_CACHE_MAX = 10_000
DEFAULT_FLOW_METRIC_CACHE_MAX = 100_000
BROWSER_OR_CONTAINER_PROCESSES = {
    "brave.exe",
    "chrome.exe",
    "discord.exe",
    "electron.exe",
    "firefox.exe",
    "msedge.exe",
    "opera.exe",
    "slack.exe",
    "telegram.exe",
}


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _safe_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))


def _timestamp(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return time.time()


def _domain(value: Any) -> str:
    normalized = str(value or "").strip().lower().rstrip(".")
    if ":" in normalized and normalized.count(":") == 1:
        normalized = normalized.split(":", 1)[0]
    if (
        not normalized
        or len(normalized) > 253
        or "/" in normalized
        or "@" in normalized
    ):
        return ""
    return redact_sensitive_text(normalized)


def _safe_ip(value: Any) -> str:
    candidate = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def _percentile(values: deque[float], percentile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, int((len(ordered) - 1) * percentile))
    return round(ordered[index], 3)


@dataclass(frozen=True)
class ServiceFingerprint:
    service_name: str
    category: str
    domain_patterns: tuple[str, ...]
    sni_patterns: tuple[str, ...]
    http_host_patterns: tuple[str, ...]
    asn_org_patterns: tuple[str, ...]
    cdn: bool = False
    risk_notes: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ServiceFingerprint":
        service_name = str(value.get("service_name") or "").strip()
        category = str(value.get("category") or "").strip()
        domain_patterns = _patterns(value.get("domain_patterns"))
        if not service_name or not category or not domain_patterns:
            raise ValueError("InvalidServiceFingerprint")
        return cls(
            service_name=service_name[:100],
            category=category[:100],
            domain_patterns=domain_patterns,
            sni_patterns=_patterns(value.get("sni_patterns")) or domain_patterns,
            http_host_patterns=_patterns(value.get("http_host_patterns"))
            or domain_patterns,
            asn_org_patterns=tuple(
                str(item).strip().lower()[:100]
                for item in value.get("asn_org_patterns") or []
                if str(item).strip()
            ),
            cdn=bool(value.get("cdn")),
            risk_notes=redact_sensitive_text(str(value.get("risk_notes") or ""))[:500],
        )


def _patterns(value: Any) -> tuple[str, ...]:
    return tuple(
        pattern
        for item in (value if isinstance(value, list) else [])
        if (pattern := _domain(item))
    )


@dataclass(frozen=True)
class ServiceAttributionResult:
    application_name: str
    service_name: str
    service_category: str
    domain: str
    destination_ip: str
    destination_port: int
    attribution_confidence: str
    confidence_score: int
    attribution_reasons: tuple[str, ...]
    attribution_sources: tuple[str, ...]
    is_encrypted: bool
    is_unknown: bool
    is_cdn: bool
    is_proxy_or_vpn_suspected: bool
    risk_hint: str

    def to_dict(self) -> dict[str, Any]:
        return redact_sensitive_data(asdict(self))


class ServiceAttributionEngine:
    """Deterministic, metadata-only destination attribution with local state."""

    def __init__(
        self,
        registry_path: str | Path | None = None,
        *,
        enabled: bool = True,
        dns_window_sec: int = 300,
        max_reasons: int = 8,
        unknown_rate_warn: float = 0.75,
        dns_cache_max: int = DEFAULT_DNS_CACHE_MAX,
        flow_metric_cache_max: int = DEFAULT_FLOW_METRIC_CACHE_MAX,
    ) -> None:
        self.enabled = bool(enabled)
        self.registry_path = Path(registry_path or DEFAULT_REGISTRY_PATH)
        self.dns_window_sec = _safe_int(dns_window_sec, 300, 1, 3600)
        self.max_reasons = _safe_int(max_reasons, 8, 1, 20)
        self.unknown_rate_warn = max(0.0, min(float(unknown_rate_warn), 1.0))
        self.dns_cache_max = _safe_int(
            dns_cache_max, DEFAULT_DNS_CACHE_MAX, 1, 1_000_000
        )
        self.flow_metric_cache_max = _safe_int(
            flow_metric_cache_max,
            DEFAULT_FLOW_METRIC_CACHE_MAX,
            1,
            1_000_000,
        )
        self._lock = threading.RLock()
        self._dns_by_ip: OrderedDict[str, deque[tuple[float, str]]] = OrderedDict()
        self._latencies: deque[float] = deque(maxlen=512)
        self._flow_outcomes: OrderedDict[str, tuple[bool, str, bool, bool]] = (
            OrderedDict()
        )
        self._attributed = self._unknown = 0
        self._high = self._medium = self._low = 0
        self._encrypted_unknown = self._cdn_only = self._errors = 0
        self._last_error = ""
        self._registry_loaded = False
        self._fingerprints = self._load_registry()

    @classmethod
    def from_env(cls) -> "ServiceAttributionEngine":
        try:
            unknown_rate = float(
                os.environ.get("NETBOT_SERVICE_ATTRIBUTION_UNKNOWN_RATE_WARN", "0.75")
            )
        except ValueError:
            unknown_rate = 0.75
        return cls(
            os.environ.get("NETBOT_SERVICE_ATTRIBUTION_REGISTRY")
            or DEFAULT_REGISTRY_PATH,
            enabled=_env_bool("NETBOT_SERVICE_ATTRIBUTION_ENABLED", True),
            dns_window_sec=_safe_int(
                os.environ.get("NETBOT_SERVICE_ATTRIBUTION_DNS_WINDOW_SEC"),
                300,
                1,
                3600,
            ),
            max_reasons=_safe_int(
                os.environ.get("NETBOT_SERVICE_ATTRIBUTION_MAX_REASONS"),
                8,
                1,
                20,
            ),
            unknown_rate_warn=unknown_rate,
        )

    def _load_registry(self) -> tuple[ServiceFingerprint, ...]:
        try:
            payload = json.loads(self.registry_path.read_text(encoding="utf-8"))
            rows = payload.get("services") if isinstance(payload, dict) else payload
            if not isinstance(rows, list):
                raise ValueError("InvalidServiceRegistry")
            fingerprints: list[ServiceFingerprint] = []
            for row in rows:
                try:
                    if isinstance(row, dict):
                        fingerprints.append(ServiceFingerprint.from_dict(row))
                except (TypeError, ValueError):
                    continue
            if not fingerprints:
                raise ValueError("EmptyServiceRegistry")
            self._registry_loaded = True
            return tuple(fingerprints)
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self._last_error = type(exc).__name__
            return ()

    def enrich(self, packet: dict[str, Any]) -> dict[str, Any]:
        result = self.attribute(packet)
        public = result.to_dict()
        packet["service_attribution"] = public
        packet.update(
            {
                "service_name": public["service_name"],
                "service_category": public["service_category"],
                "service_domain": public["domain"],
                "service_confidence": public["attribution_confidence"],
                "service_confidence_score": public["confidence_score"],
                "service_reasons": list(public["attribution_reasons"]),
                "service_sources": list(public["attribution_sources"]),
                "service_encrypted": public["is_encrypted"],
                "service_unknown": public["is_unknown"],
                "service_is_cdn": public["is_cdn"],
                "service_risk_hint": public["risk_hint"],
            }
        )
        return public

    def attribute(self, packet: dict[str, Any]) -> ServiceAttributionResult:
        started = time.perf_counter()
        try:
            self._observe_dns(packet)
            result = self._attribute(packet)
        except Exception as exc:  # pragma: no cover - defensive hot-path guard
            with self._lock:
                self._errors += 1
                self._last_error = type(exc).__name__
            result = self._unknown_result(
                packet, "Attribution metadata could not be evaluated safely."
            )
        self._record_result(packet, result, (time.perf_counter() - started) * 1000.0)
        return result

    def _attribute(self, packet: dict[str, Any]) -> ServiceAttributionResult:
        if not self.enabled:
            return self._unknown_result(packet, "Service attribution is disabled.")

        application = redact_sensitive_text(str(packet.get("process_name") or ""))[:120]
        destination_ip = _safe_ip(
            packet.get("remote_ip") or packet.get("dst") or packet.get("destination_ip")
        )
        destination_port = _safe_int(
            packet.get("dport")
            or packet.get("destination_port")
            or packet.get("sport"),
            0,
            0,
            65535,
        )
        encrypted = self._is_encrypted(packet, destination_port)
        proxy_or_vpn = self._is_proxy_or_vpn(packet, application)
        org = redact_sensitive_text(
            str(
                packet.get("org")
                or packet.get("asn_org")
                or packet.get("organization")
                or ""
            )
        )[:200]

        candidates: list[tuple[str, str]] = []
        for source, value in (
            ("http_host", packet.get("http_host")),
            (
                "tls_sni",
                packet.get("tls_sni")
                or packet.get("sni")
                or packet.get("quic_sni")
                or packet.get("quic_server_name"),
            ),
            ("dns", packet.get("dns_qname")),
        ):
            if normalized := _domain(value):
                candidates.append((source, normalized))
        for value in packet.get("resolved_domains") or []:
            if normalized := _domain(value):
                candidates.append(("dns", normalized))
        if destination_ip:
            for value in self._recent_domains(destination_ip, packet):
                candidates.append(("dns", value))

        evidence: list[tuple[str, str, ServiceFingerprint]] = []
        for source, candidate in candidates:
            fingerprint = self._match(candidate, source)
            if fingerprint:
                evidence.append((source, candidate, fingerprint))

        if evidence:
            return self._result_from_evidence(
                packet,
                evidence,
                application,
                destination_ip,
                destination_port,
                encrypted,
                proxy_or_vpn,
                org,
            )

        org_match = self._match_org(org)
        if org_match:
            if org_match.cdn:
                service_name = "CDN only"
                category = "Unknown / CDN"
                risk_hint = "shared_cdn_only"
            else:
                service_name = f"{org_match.service_name} Services"
                category = org_match.category
                risk_hint = "organization_only_attribution"
            return ServiceAttributionResult(
                application,
                service_name,
                category,
                "",
                destination_ip,
                destination_port,
                "low",
                30,
                (f"ASN organization matched {org}", "No service domain was visible."),
                ("asn_org",),
                encrypted,
                False,
                org_match.cdn,
                proxy_or_vpn,
                risk_hint,
            )
        return self._unknown_result(packet)

    def _result_from_evidence(
        self,
        packet: dict[str, Any],
        evidence: list[tuple[str, str, ServiceFingerprint]],
        application: str,
        destination_ip: str,
        destination_port: int,
        encrypted: bool,
        proxy_or_vpn: bool,
        org: str,
    ) -> ServiceAttributionResult:
        priority = {"http_host": 3, "tls_sni": 2, "dns": 1}
        selected_source, selected_domain, selected = max(
            evidence, key=lambda item: priority[item[0]]
        )
        agreeing = [
            item for item in evidence if item[2].service_name == selected.service_name
        ]
        conflicting = any(
            item[2].service_name != selected.service_name for item in evidence
        )
        base_scores = {"http_host": 90, "tls_sni": 80, "dns": 60}
        score = base_scores[selected_source]
        sources: list[str] = []
        reasons: list[str] = []
        source_labels = {
            "http_host": "HTTP Host",
            "tls_sni": "TLS SNI",
            "dns": "Recent DNS query",
        }
        for source, domain, _fingerprint in agreeing:
            if source not in sources:
                sources.append(source)
                reasons.append(f"{source_labels[source]} matched {domain}")
                if source != selected_source:
                    score += 10 if source == "dns" else 15
        if org and any(pattern in org.lower() for pattern in selected.asn_org_patterns):
            sources.append("asn_org")
            reasons.append(f"ASN organization matched {org}")
            score += 15
        reasons.append(f"Domain pattern matched {selected.service_name} fingerprint")
        if "fingerprint" not in sources:
            sources.append("fingerprint")
        if conflicting:
            reasons.append("Conflicting service metadata reduced confidence.")
            score -= 20
        score = max(0, min(score, 100))
        confidence = "high" if score >= 80 else "medium" if score >= 50 else "low"
        return ServiceAttributionResult(
            application,
            selected.service_name,
            selected.category,
            selected_domain,
            destination_ip,
            destination_port,
            confidence,
            score,
            tuple(reasons[: self.max_reasons]),
            tuple(dict.fromkeys(sources)),
            encrypted,
            False,
            selected.cdn,
            proxy_or_vpn,
            f"known_{selected.category.lower().replace(' ', '_').replace('/', '_')}_service",
        )

    def _unknown_result(
        self, packet: dict[str, Any], reason: str | None = None
    ) -> ServiceAttributionResult:
        application = redact_sensitive_text(str(packet.get("process_name") or ""))[:120]
        destination_ip = _safe_ip(packet.get("remote_ip") or packet.get("dst"))
        destination_port = _safe_int(
            packet.get("dport") or packet.get("sport"), 0, 0, 65535
        )
        encrypted = self._is_encrypted(packet, destination_port)
        reasons = [
            reason or "No visible DNS, SNI, or HTTP Host evidence was available."
        ]
        if application.lower() in BROWSER_OR_CONTAINER_PROCESSES:
            reasons.append(
                "Browser or container process identity alone is not service evidence."
            )
        if encrypted:
            reasons.append("Destination appears encrypted.")
        return ServiceAttributionResult(
            application,
            "Unknown encrypted destination" if encrypted else "Unknown",
            "Unknown",
            "",
            destination_ip,
            destination_port,
            "low" if encrypted else "unknown",
            20 if encrypted else (5 if application else 0),
            tuple(reasons[: self.max_reasons]),
            (),
            encrypted,
            True,
            False,
            self._is_proxy_or_vpn(packet, application),
            "unknown_encrypted_destination" if encrypted else "unknown_destination",
        )

    def _match(self, domain: str, source: str) -> ServiceFingerprint | None:
        best: tuple[int, ServiceFingerprint] | None = None
        for fingerprint in self._fingerprints:
            patterns = (
                fingerprint.http_host_patterns
                if source == "http_host"
                else (
                    fingerprint.sni_patterns
                    if source == "tls_sni"
                    else fingerprint.domain_patterns
                )
            )
            for pattern in patterns:
                if fnmatch(domain, pattern) or domain == pattern.removeprefix("*."):
                    specificity = len(pattern.replace("*", ""))
                    if best is None or specificity > best[0]:
                        best = (specificity, fingerprint)
        return best[1] if best else None

    def _match_org(self, org: str) -> ServiceFingerprint | None:
        lowered = org.lower()
        if not lowered:
            return None
        matches = [
            fingerprint
            for fingerprint in self._fingerprints
            if any(pattern in lowered for pattern in fingerprint.asn_org_patterns)
        ]
        matches.sort(
            key=lambda fingerprint: (fingerprint.cdn, len(fingerprint.domain_patterns))
        )
        return matches[0] if matches else None

    def _observe_dns(self, packet: dict[str, Any]) -> None:
        domain = _domain(packet.get("dns_qname"))
        if not domain:
            return
        answers: list[Any] = []
        for key in ("dns_answer_ips", "resolved_ips", "dns_answers"):
            value = packet.get(key)
            answers.extend(
                value if isinstance(value, list) else [value] if value else []
            )
        if packet.get("dns_answer_ip"):
            answers.append(packet["dns_answer_ip"])
        observed_at = _timestamp(packet.get("ts") or packet.get("timestamp"))
        with self._lock:
            for answer in answers:
                candidate = (
                    answer.get("ip") or answer.get("address")
                    if isinstance(answer, dict)
                    else answer
                )
                if ip := _safe_ip(candidate):
                    values = self._dns_by_ip.setdefault(ip, deque(maxlen=20))
                    values.append((observed_at, domain))
                    self._dns_by_ip.move_to_end(ip)
                    if len(self._dns_by_ip) > self.dns_cache_max:
                        self._dns_by_ip.popitem(last=False)

    def _recent_domains(self, destination_ip: str, packet: dict[str, Any]) -> list[str]:
        now = _timestamp(packet.get("ts") or packet.get("timestamp"))
        cutoff = now - self.dns_window_sec
        with self._lock:
            values = self._dns_by_ip.get(destination_ip, deque())
            if destination_ip in self._dns_by_ip:
                self._dns_by_ip.move_to_end(destination_ip)
            recent = [item for item in values if item[0] >= cutoff]
            recent.sort(key=lambda item: abs(now - item[0]))
            return [domain for _observed_at, domain in recent]

    @staticmethod
    def _is_encrypted(packet: dict[str, Any], port: int) -> bool:
        protocol = str(
            packet.get("app_protocol") or packet.get("protocol") or ""
        ).upper()
        return port in {443, 8443, 9443} or protocol in {"TLS", "HTTPS", "QUIC"}

    @staticmethod
    def _is_proxy_or_vpn(packet: dict[str, Any], application: str) -> bool:
        text = " ".join(
            [
                application,
                str(packet.get("service_category") or ""),
                str(packet.get("interface") or ""),
            ]
        ).lower()
        return bool(
            packet.get("proxy") or packet.get("vpn") or "vpn" in text or "proxy" in text
        )

    @staticmethod
    def _flow_metric_key(packet: dict[str, Any]) -> str:
        explicit = packet.get("flow_id") or packet.get("flow_key")
        if explicit:
            return str(explicit)
        return "|".join(
            str(value or "-")
            for value in (
                packet.get("src"),
                packet.get("dst") or packet.get("remote_ip"),
                packet.get("sport"),
                packet.get("dport"),
                packet.get("proto") or packet.get("transport"),
                packet.get("direction"),
            )
        )

    def _adjust_outcome(
        self, outcome: tuple[bool, str, bool, bool], delta: int
    ) -> None:
        is_unknown, confidence, encrypted_unknown, cdn_only = outcome
        if is_unknown:
            self._unknown += delta
        else:
            self._attributed += delta
        if confidence == "high":
            self._high += delta
        elif confidence == "medium":
            self._medium += delta
        elif confidence == "low":
            self._low += delta
        if encrypted_unknown:
            self._encrypted_unknown += delta
        if cdn_only:
            self._cdn_only += delta

    def _record_result(
        self,
        packet: dict[str, Any],
        result: ServiceAttributionResult,
        latency_ms: float,
    ) -> None:
        with self._lock:
            self._latencies.append(latency_ms)
            flow_key = self._flow_metric_key(packet)
            outcome = (
                result.is_unknown,
                result.attribution_confidence,
                result.is_unknown and result.is_encrypted,
                result.service_name == "CDN only",
            )
            previous = self._flow_outcomes.get(flow_key)
            if previous == outcome:
                return
            if previous:
                self._adjust_outcome(previous, -1)
            self._flow_outcomes[flow_key] = outcome
            self._flow_outcomes.move_to_end(flow_key)
            self._adjust_outcome(outcome, 1)
            if len(self._flow_outcomes) > self.flow_metric_cache_max:
                self._flow_outcomes.popitem(last=False)

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            total = self._attributed + self._unknown
            unknown_rate = self._unknown / total if total else 0.0
            avg_latency = (
                round(sum(self._latencies) / len(self._latencies), 3)
                if self._latencies
                else 0.0
            )
            p95_latency = _percentile(self._latencies, 0.95)
            reasons: list[str] = []
            if self.enabled and not self._registry_loaded:
                reasons.append("service_attribution_registry_error")
            if p95_latency >= 25.0:
                reasons.append("service_attribution_high_latency")
            if self._errors:
                reasons.append("service_attribution_errors")
            if total >= 20 and unknown_rate >= self.unknown_rate_warn:
                reasons.append("service_attribution_high_unknown_rate")
            health = "healthy"
            if reasons:
                health = "degraded"
            if self.enabled and not self._fingerprints:
                health = "critical"
            if self._errors >= 25:
                health = "critical"
            return {
                "enabled": self.enabled,
                "health": health,
                "registry_size": len(self._fingerprints),
                "attributed_flows_total": self._attributed,
                "unknown_flows_total": self._unknown,
                "high_confidence_total": self._high,
                "medium_confidence_total": self._medium,
                "low_confidence_total": self._low,
                "encrypted_unknown_total": self._encrypted_unknown,
                "cdn_only_total": self._cdn_only,
                "attribution_errors_total": self._errors,
                "avg_attribution_latency_ms": avg_latency,
                "p95_attribution_latency_ms": p95_latency,
                "last_error": self._last_error,
                "pressure_reasons": reasons,
            }

    def reset_runtime(self) -> None:
        with self._lock:
            self._dns_by_ip.clear()
            self._latencies.clear()
            self._flow_outcomes.clear()
            self._attributed = self._unknown = 0
            self._high = self._medium = self._low = 0
            self._encrypted_unknown = self._cdn_only = self._errors = 0
            if self._registry_loaded:
                self._last_error = ""


_default_engine: ServiceAttributionEngine | None = None
_default_engine_lock = threading.Lock()


def default_service_attribution_engine() -> ServiceAttributionEngine:
    global _default_engine
    with _default_engine_lock:
        if _default_engine is None:
            _default_engine = ServiceAttributionEngine.from_env()
        return _default_engine


def attribute_service(packet: dict[str, Any]) -> dict[str, Any]:
    public = default_service_attribution_engine().attribute(packet).to_dict()
    public.update(
        {
            "service_domain": public["domain"],
            "service_confidence": public["attribution_confidence"],
            "service_reasons": list(public["attribution_reasons"]),
            "service_sources": list(public["attribution_sources"]),
            "service_encrypted": public["is_encrypted"],
            "service_unknown": public["is_unknown"],
        }
    )
    if public["is_unknown"] and public["is_encrypted"]:
        public["service_name"] = "Unknown Encrypted"
    return public


def enrich_service_attribution(packet: dict[str, Any]) -> dict[str, Any]:
    return default_service_attribution_engine().enrich(packet)


__all__ = [
    "BROWSER_OR_CONTAINER_PROCESSES",
    "ServiceAttributionEngine",
    "ServiceAttributionResult",
    "ServiceFingerprint",
    "attribute_service",
    "default_service_attribution_engine",
    "enrich_service_attribution",
]
