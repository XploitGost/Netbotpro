from __future__ import annotations

import os
import threading
import time
import uuid
from collections import OrderedDict, deque
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from statistics import mean
from typing import Any

from backend.app.services.redaction import redact_sensitive_data, redact_sensitive_text

SEVERITIES = ("info", "low", "medium", "high", "critical")
INCIDENT_TYPES = {
    "possible_beaconing": {
        "title": "Possible Beaconing",
        "steps": [
            "Review the destination, process, and connection timing.",
            "Compare related DNS and encrypted-flow evidence.",
        ],
        "false_positive": "Background updates and long-lived application sessions can look periodic.",
    },
    "possible_port_scan": {
        "title": "Possible Port Scan / Connection Sweep",
        "steps": [
            "Review the source host and targeted ports or destinations.",
            "Confirm whether an authorized discovery tool was running.",
        ],
        "false_positive": "Inventory, monitoring, and vulnerability scanners may be authorized.",
    },
    "suspicious_dns": {
        "title": "Suspicious DNS Activity",
        "steps": [
            "Review related domains and DNS response patterns.",
            "Compare the requesting process with expected host activity.",
        ],
        "false_positive": "CDNs and security products may generate many unique or high-entropy names.",
    },
    "unusual_external_service": {
        "title": "Unusual External Service",
        "steps": [
            "Validate the external destination and attributed service.",
            "Confirm that the source application is expected to make this connection.",
        ],
        "false_positive": "New SaaS endpoints and shared CDN infrastructure can reduce attribution confidence.",
    },
    "data_exfiltration_indicator": {
        "title": "Data Exfiltration Indicator",
        "steps": [
            "Review outbound byte volume, duration, and destination ownership.",
            "Validate the source process and related alerts without exposing payload data.",
        ],
        "false_positive": "Authorized backups, uploads, and software distribution can produce high outbound volume.",
    },
}


def _env_bool(name: str, default: bool) -> bool:
    value = str(os.environ.get(name, str(default))).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if minimum <= value <= maximum else default


def _parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        except (TypeError, ValueError):
            parsed = datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _string(value: Any, limit: int = 300) -> str:
    return redact_sensitive_text(str(value or "").strip())[:limit]


def _list(value: Any, limit: int = 20) -> list[str]:
    rows = value if isinstance(value, (list, tuple, set)) else [value]
    return list(dict.fromkeys(_string(item) for item in rows if _string(item)))[:limit]


class IncidentCorrelationEngine:
    """Bounded, deterministic correlation over already-derived metadata signals."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        correlation_window_sec: int = 600,
        max_open: int = 1000,
        max_signals_per_incident: int = 500,
        retention_hours: int = 24,
        min_severity: str = "low",
        high_signal_threshold: int = 5,
        critical_signal_threshold: int = 10,
    ) -> None:
        self.enabled = bool(enabled)
        self.correlation_window_sec = max(10, min(int(correlation_window_sec), 86400))
        self.max_open = max(1, min(int(max_open), 100_000))
        self.max_signals_per_incident = max(2, min(int(max_signals_per_incident), 5000))
        self.retention_hours = max(1, min(int(retention_hours), 8760))
        self.min_severity = min_severity if min_severity in SEVERITIES else "low"
        self.high_signal_threshold = max(2, int(high_signal_threshold))
        self.critical_signal_threshold = max(
            self.high_signal_threshold + 1, int(critical_signal_threshold)
        )
        self._lock = threading.RLock()
        self._incidents: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._pending: OrderedDict[str, deque[dict[str, Any]]] = OrderedDict()
        self._latencies: deque[float] = deque(maxlen=512)
        self._created_total = 0
        self._updated_total = 0
        self._signals_received = 0
        self._signals_correlated = 0
        self._signals_ignored = 0
        self._signals_dropped = 0
        self._errors = 0
        self._last_created_at = ""
        self._last_updated_at = ""
        self._last_error = ""

    @classmethod
    def from_env(cls) -> "IncidentCorrelationEngine":
        return cls(
            enabled=_env_bool("NETBOT_INCIDENTS_ENABLED", True),
            correlation_window_sec=_env_int(
                "NETBOT_INCIDENT_CORRELATION_WINDOW_SEC", 600, 10, 86400
            ),
            max_open=_env_int("NETBOT_INCIDENT_MAX_OPEN", 1000, 1, 100_000),
            max_signals_per_incident=_env_int(
                "NETBOT_INCIDENT_MAX_SIGNALS_PER_INCIDENT", 500, 2, 5000
            ),
            retention_hours=_env_int("NETBOT_INCIDENT_RETENTION_HOURS", 24, 1, 8760),
            min_severity=os.environ.get("NETBOT_INCIDENT_MIN_SEVERITY", "low").lower(),
            high_signal_threshold=_env_int(
                "NETBOT_INCIDENT_HIGH_SIGNAL_THRESHOLD", 5, 2, 1000
            ),
            critical_signal_threshold=_env_int(
                "NETBOT_INCIDENT_CRITICAL_SIGNAL_THRESHOLD", 10, 3, 5000
            ),
        )

    def correlate(
        self,
        *,
        packet: dict[str, Any],
        flow: dict[str, Any] | None,
        alerts: list[dict[str, Any]],
        expert_items: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        signals = self._derive_signals(packet, flow or {}, alerts, expert_items)
        updated: OrderedDict[str, dict[str, Any]] = OrderedDict()
        for signal in signals:
            incident = self.ingest_signal(signal)
            if incident:
                updated[incident["incident_id"]] = incident
        return list(updated.values())

    def ingest_signal(self, signal: dict[str, Any]) -> dict[str, Any] | None:
        started = time.perf_counter()
        with self._lock:
            self._signals_received += 1
            try:
                normalized = self._normalize_signal(signal)
                if not self.enabled or not normalized:
                    self._signals_ignored += 1
                    return None
                self._cleanup_locked(normalized["timestamp_dt"])
                incident = self._matching_incident_locked(normalized)
                if incident is None:
                    pending = self._pending_for_locked(normalized)
                    pending.append(normalized)
                    while len(pending) > self.max_signals_per_incident:
                        pending.popleft()
                        self._signals_dropped += 1
                    if not self._threshold_met(pending):
                        self._signals_ignored += 1
                        return None
                    incident = self._create_locked(list(pending))
                    pending.clear()
                else:
                    self._update_locked(incident, normalized)
                self._signals_correlated += 1
                return self._public(incident)
            except Exception as exc:  # pragma: no cover - defensive hot path
                self._errors += 1
                self._last_error = type(exc).__name__
                self._signals_ignored += 1
                return None
            finally:
                self._latencies.append((time.perf_counter() - started) * 1000.0)

    def list_incidents(
        self,
        *,
        status: str = "open",
        severity: str = "",
        limit: int = 100,
        since: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            self._cleanup_locked(datetime.now(timezone.utc))
            since_dt = _parse_time(since) if since else None
            items = []
            for incident in reversed(self._incidents.values()):
                if status != "all" and incident["status"] != status:
                    continue
                if severity and incident["severity"] != severity:
                    continue
                if since_dt and _parse_time(incident["last_seen"]) < since_dt:
                    continue
                items.append(self._public(incident))
                if len(items) >= max(1, min(int(limit), 1000)):
                    break
            return {
                "items": items,
                "count": len(items),
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self._lock:
            incident = self._incidents.get(str(incident_id))
            return self._public(incident) if incident else None

    def reset(self) -> None:
        with self._lock:
            self._incidents.clear()
            self._pending.clear()

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            incidents = list(self._incidents.values())
            open_total = sum(row["status"] == "open" for row in incidents)
            high_total = sum(row["severity"] == "high" for row in incidents)
            critical_total = sum(row["severity"] == "critical" for row in incidents)
            reasons: list[str] = []
            avg_latency = round(mean(self._latencies), 3) if self._latencies else 0.0
            ordered = sorted(self._latencies)
            p95 = (
                round(ordered[min(len(ordered) - 1, int((len(ordered) - 1) * 0.95))], 3)
                if ordered
                else 0.0
            )
            if open_total >= max(1, int(self.max_open * 0.8)):
                reasons.append("incident_high_open_count")
            if self._signals_dropped:
                reasons.append("incident_dropped_signals")
            if p95 >= 50.0:
                reasons.append("incident_correlation_latency")
            if self._errors:
                reasons.append("incident_engine_errors")
            health = "degraded" if reasons else "healthy"
            if self._errors >= 3 or open_total >= self.max_open:
                health = "critical"
            return redact_sensitive_data(
                {
                    "enabled": self.enabled,
                    "health": health,
                    "open_total": open_total,
                    "created_total": self._created_total,
                    "updated_total": self._updated_total,
                    "resolved_total": sum(
                        row["status"] == "resolved" for row in incidents
                    ),
                    "suppressed_total": sum(
                        row["status"] == "suppressed" for row in incidents
                    ),
                    "signals_received_total": self._signals_received,
                    "signals_correlated_total": self._signals_correlated,
                    "signals_ignored_total": self._signals_ignored,
                    "signals_dropped_total": self._signals_dropped,
                    "high_severity_total": high_total,
                    "critical_severity_total": critical_total,
                    "avg_correlation_latency_ms": avg_latency,
                    "p95_correlation_latency_ms": p95,
                    "max_open_incidents": self.max_open,
                    "max_signals_per_incident": self.max_signals_per_incident,
                    "last_created_at": self._last_created_at,
                    "last_updated_at": self._last_updated_at,
                    "last_error": self._last_error,
                    "pressure_reasons": reasons,
                }
            )

    def _derive_signals(
        self,
        packet: dict[str, Any],
        flow: dict[str, Any],
        alerts: list[dict[str, Any]],
        experts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        base = {
            "timestamp": packet.get("ts") or packet.get("timestamp"),
            "source_host": packet.get("src") or flow.get("src_ip"),
            "destination_host": packet.get("dst") or flow.get("dst_ip"),
            "application": packet.get("process_name") or flow.get("process_name"),
            "service": packet.get("service_name") or flow.get("service_name"),
            "domain": packet.get("service_domain") or flow.get("service_domain"),
            "category": packet.get("service_category") or flow.get("service_category"),
            "flow_key": flow.get("flow_id") or packet.get("flow_id"),
            "bytes_out": flow.get("bytes_sent") or packet.get("length") or 0,
        }
        signals: list[dict[str, Any]] = []
        for alert in alerts:
            text = " ".join(
                str(alert.get(key) or "")
                for key in ("attack_type", "detail", "risk_reasons")
            )
            incident_type = self._classify(text, packet, flow)
            if incident_type:
                signals.append(
                    {
                        **base,
                        "incident_type": incident_type,
                        "source": "alert",
                        "summary": alert.get("attack_type") or alert.get("detail"),
                        "severity": alert.get("severity") or "medium",
                        "alert_id": alert.get("id"),
                        "risk_reasons": alert.get("risk_reasons")
                        or [alert.get("detail")],
                    }
                )
        combined = " ".join(
            str(value or "")
            for value in [
                flow.get("risk_reasons"),
                packet.get("service_risk_hint"),
                packet.get("service_name"),
            ]
        )
        flow_type = self._classify(combined, packet, flow)
        if flow_type:
            signals.append(
                {
                    **base,
                    "incident_type": flow_type,
                    "source": "flow",
                    "summary": self._summary_for(flow_type, packet),
                    "severity": flow.get("risk_level") or "low",
                    "risk_reasons": flow.get("risk_reasons")
                    or packet.get("service_reasons"),
                }
            )
        for expert in experts[:5]:
            text = " ".join(
                str(expert.get(key) or "") for key in ("summary", "message", "category")
            )
            incident_type = self._classify(text, packet, flow)
            if incident_type:
                signals.append(
                    {
                        **base,
                        "incident_type": incident_type,
                        "source": "expert_info",
                        "summary": expert.get("summary") or expert.get("message"),
                        "severity": expert.get("severity") or "low",
                        "risk_reasons": [text],
                    }
                )
        return signals

    @staticmethod
    def _classify(text: str, packet: dict[str, Any], flow: dict[str, Any]) -> str:
        lowered = text.lower()
        if (
            any(word in lowered for word in ("exfil", "large outbound", "upload spike"))
            or int(flow.get("bytes_sent") or 0) >= 50_000_000
        ):
            return "data_exfiltration_indicator"
        if any(
            word in lowered
            for word in (
                "port scan",
                "connection sweep",
                "scan burst",
                "many destination ports",
            )
        ):
            return "possible_port_scan"
        if any(
            word in lowered
            for word in (
                "dns entropy",
                "nxdomain",
                "dga",
                "dns tunnel",
                "suspicious dns",
            )
        ):
            return "suspicious_dns"
        encrypted = bool(packet.get("service_encrypted")) or str(
            flow.get("app_protocol") or ""
        ).upper() in {"TLS", "QUIC"}
        unknown = bool(packet.get("service_unknown")) or "unknown encrypted" in lowered
        if encrypted and unknown:
            return "possible_beaconing"
        if unknown or any(
            word in lowered
            for word in (
                "unusual destination",
                "rare external",
                "low confidence attribution",
            )
        ):
            return "unusual_external_service"
        return ""

    @staticmethod
    def _summary_for(incident_type: str, packet: dict[str, Any]) -> str:
        service = _string(packet.get("service_name") or "unknown service", 100)
        return f"Observed metadata associated with {service} for {INCIDENT_TYPES[incident_type]['title'].lower()}."

    def _normalize_signal(self, value: dict[str, Any]) -> dict[str, Any] | None:
        if (
            not isinstance(value, dict)
            or value.get("incident_type") not in INCIDENT_TYPES
        ):
            return None
        safe = redact_sensitive_data(deepcopy(value))
        timestamp_dt = _parse_time(safe.get("timestamp"))
        severity = str(safe.get("severity") or "low").lower()
        if severity not in SEVERITIES:
            severity = "low"
        return {
            "signal_id": _string(safe.get("signal_id") or uuid.uuid4().hex, 80),
            "incident_type": safe["incident_type"],
            "timestamp": timestamp_dt.isoformat(),
            "timestamp_dt": timestamp_dt,
            "source_host": _string(safe.get("source_host"), 100),
            "destination_host": _string(safe.get("destination_host"), 100),
            "application": _string(safe.get("application"), 100),
            "service": _string(safe.get("service"), 100),
            "domain": _string(safe.get("domain"), 253),
            "category": _string(safe.get("category"), 100),
            "flow_key": _string(safe.get("flow_key"), 100),
            "alert_id": _string(safe.get("alert_id"), 100),
            "agent_id": _string(safe.get("agent_id"), 100),
            "source": _string(safe.get("source") or "analysis", 80),
            "summary": _string(safe.get("summary") or "Related analysis signal", 500),
            "severity": severity,
            "risk_reasons": _list(safe.get("risk_reasons"), 20),
            "bytes_out": max(0, int(safe.get("bytes_out") or 0)),
        }

    def _pending_for_locked(self, signal: dict[str, Any]) -> deque[dict[str, Any]]:
        key = f"{signal['incident_type']}|{signal['source_host'] or signal['flow_key'] or signal['destination_host']}"
        pending = self._pending.setdefault(key, deque())
        cutoff = signal["timestamp_dt"] - timedelta(seconds=self.correlation_window_sec)
        while pending and pending[0]["timestamp_dt"] < cutoff:
            pending.popleft()
        self._pending.move_to_end(key)
        while len(self._pending) > self.max_open * 2:
            _, removed = self._pending.popitem(last=False)
            self._signals_dropped += len(removed)
        return pending

    @staticmethod
    def _threshold_met(signals: deque[dict[str, Any]]) -> bool:
        if len(signals) < 2:
            return False
        dimensions = {signal.get("source") for signal in signals}
        severe = any(
            SEVERITIES.index(signal["severity"]) >= SEVERITIES.index("high")
            for signal in signals
        )
        return len(dimensions) >= 2 or severe or len(signals) >= 3

    def _matching_incident_locked(
        self, signal: dict[str, Any]
    ) -> dict[str, Any] | None:
        for incident in reversed(self._incidents.values()):
            if (
                incident["status"] != "open"
                or incident["type"] != signal["incident_type"]
            ):
                continue
            if (
                abs(
                    (
                        signal["timestamp_dt"] - _parse_time(incident["last_seen"])
                    ).total_seconds()
                )
                > self.correlation_window_sec
            ):
                continue
            source_match = (
                signal["source_host"]
                and signal["source_host"] in incident["source_hosts"]
            )
            context_match = any(
                [
                    signal["flow_key"]
                    and signal["flow_key"] in incident["related_flows"],
                    signal["domain"] and signal["domain"] in incident["domains"],
                    signal["service"] and signal["service"] in incident["services"],
                    signal["destination_host"]
                    and signal["destination_host"] in incident["destination_hosts"],
                ]
            )
            if source_match and (context_match or incident["signal_count"] >= 2):
                return incident
        return None

    def _create_locked(self, signals: list[dict[str, Any]]) -> dict[str, Any]:
        while len(self._incidents) >= self.max_open:
            self._incidents.popitem(last=False)
            self._signals_dropped += 1
        now = datetime.now(timezone.utc).isoformat()
        first = signals[0]
        definition = INCIDENT_TYPES[first["incident_type"]]
        incident = {
            "incident_id": f"inc-{uuid.uuid4().hex[:16]}",
            "title": definition["title"],
            "type": first["incident_type"],
            "severity": "low",
            "confidence": "low",
            "status": "open",
            "first_seen": min(row["timestamp"] for row in signals),
            "last_seen": max(row["timestamp"] for row in signals),
            "source_hosts": [],
            "destination_hosts": [],
            "applications": [],
            "services": [],
            "domains": [],
            "categories": [],
            "related_flows": [],
            "related_alerts": [],
            "related_agents": [],
            "risk_reasons": [],
            "evidence": [],
            "timeline": [],
            "recommended_investigation_steps": definition["steps"],
            "false_positive_notes": [definition["false_positive"]],
            "correlation_reasons": [],
            "signal_count": 0,
            "created_at": now,
            "updated_at": now,
        }
        for signal in signals:
            self._apply_signal(incident, signal)
        self._incidents[incident["incident_id"]] = incident
        self._created_total += 1
        self._last_created_at = now
        return incident

    def _update_locked(self, incident: dict[str, Any], signal: dict[str, Any]) -> None:
        self._apply_signal(incident, signal)
        incident["updated_at"] = datetime.now(timezone.utc).isoformat()
        self._incidents.move_to_end(incident["incident_id"])
        self._updated_total += 1
        self._last_updated_at = incident["updated_at"]

    def _apply_signal(self, incident: dict[str, Any], signal: dict[str, Any]) -> None:
        incident["signal_count"] += 1
        incident["last_seen"] = max(incident["last_seen"], signal["timestamp"])
        mappings = (
            ("source_hosts", "source_host"),
            ("destination_hosts", "destination_host"),
            ("applications", "application"),
            ("services", "service"),
            ("domains", "domain"),
            ("categories", "category"),
            ("related_flows", "flow_key"),
            ("related_alerts", "alert_id"),
            ("related_agents", "agent_id"),
        )
        for target, source in mappings:
            value = signal[source]
            if value and value not in incident[target]:
                incident[target].append(value)
                incident[target] = incident[target][-100:]
        incident["risk_reasons"] = list(
            dict.fromkeys(incident["risk_reasons"] + signal["risk_reasons"])
        )[-100:]
        if signal["summary"] not in incident["evidence"]:
            incident["evidence"].append(signal["summary"])
            incident["evidence"] = incident["evidence"][
                -self.max_signals_per_incident :
            ]
        incident["timeline"].append(
            {
                "timestamp": signal["timestamp"],
                "event_type": "signal_correlated",
                "summary": signal["summary"],
                "source": signal["source"],
                "flow_key": signal["flow_key"],
                "alert_id": signal["alert_id"],
                "service_name": signal["service"],
                "domain": signal["domain"],
                "severity": signal["severity"],
            }
        )
        incident["timeline"] = sorted(
            incident["timeline"], key=lambda row: row["timestamp"]
        )[-self.max_signals_per_incident :]
        self._score(incident)

    def _score(self, incident: dict[str, Any]) -> None:
        count = incident["signal_count"]
        max_signal = max(
            (SEVERITIES.index(row["severity"]) for row in incident["timeline"]),
            default=1,
        )
        if count >= self.critical_signal_threshold or max_signal >= 4:
            severity = "critical"
        elif count >= self.high_signal_threshold or max_signal >= 3:
            severity = "high"
        elif count >= 3 or max_signal >= 2:
            severity = "medium"
        else:
            severity = "low"
        if SEVERITIES.index(severity) < SEVERITIES.index(self.min_severity):
            severity = self.min_severity
        incident["severity"] = severity
        dimensions = sum(
            bool(incident[key])
            for key in (
                "source_hosts",
                "related_flows",
                "services",
                "domains",
                "applications",
                "related_alerts",
            )
        )
        incident["confidence"] = (
            "high"
            if dimensions >= 5 and count >= 3
            else "medium" if dimensions >= 3 else "low"
        )
        reasons = []
        if incident["source_hosts"]:
            reasons.append("Same source host within correlation window")
        if incident["domains"]:
            reasons.append("Same service attribution domain")
        if len(incident["evidence"]) >= 2:
            reasons.append("Multiple related analysis signals")
        if incident["related_flows"]:
            reasons.append("Related flow metadata")
        incident["correlation_reasons"] = reasons

    def _cleanup_locked(self, now: datetime) -> None:
        cutoff = now - timedelta(hours=self.retention_hours)
        for incident_id in list(self._incidents):
            if _parse_time(self._incidents[incident_id]["last_seen"]) < cutoff:
                del self._incidents[incident_id]
        pending_cutoff = now - timedelta(seconds=self.correlation_window_sec)
        for key in list(self._pending):
            pending = self._pending[key]
            while pending and pending[0]["timestamp_dt"] < pending_cutoff:
                pending.popleft()
            if not pending:
                del self._pending[key]

    @staticmethod
    def _public(incident: dict[str, Any]) -> dict[str, Any]:
        return redact_sensitive_data(deepcopy(incident))


__all__ = ["IncidentCorrelationEngine", "INCIDENT_TYPES", "SEVERITIES"]
