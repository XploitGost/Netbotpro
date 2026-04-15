from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import logging
import threading
import time
from typing import Any, Callable

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.services.app_protocols import infer_app_protocol

ensure_project_root_on_path()

from core.netbotpro_sniffer_core.ip_utils import is_local_ip, is_remote_ip
from core.firewall_tools import block_ip  # noqa: E402
from core.ids_ml import MLIDS  # noqa: E402
from core.ids_rules_engine import RuleEngine  # noqa: E402
from core.ids_signature import SignatureIDS  # noqa: E402
from core.incident_engine import IncidentCorrelator  # noqa: E402
from core.score_engine import AlertScorer  # noqa: E402

logger = logging.getLogger(__name__)

AUTO_BLOCK_SCORE_THRESHOLD = 0.7
AUTO_BLOCK_COOLDOWN_SEC = 300.0
AUTO_BLOCK_MAX_TRACKED = 2048
DNS_TUNNEL_WINDOW_SEC = 90
DNS_TUNNEL_THRESHOLD = 3
TLS_NO_SNI_WINDOW_SEC = 120
TLS_NO_SNI_THRESHOLD = 4
MAX_APP_TRACKED_KEYS = 4096


class SnifferDetectionPipeline:
    def __init__(
        self,
        settings_provider: Callable[[], dict[str, Any]] | None = None,
        ids_sig: SignatureIDS | None = None,
        ids_ml: MLIDS | None = None,
        rule_engine: RuleEngine | None = None,
        scorer: AlertScorer | None = None,
        incidents: IncidentCorrelator | None = None,
    ) -> None:
        self._settings_provider = settings_provider or (lambda: {})
        self._ids_sig = ids_sig or SignatureIDS()
        self._ids_ml = ids_ml or MLIDS()
        self._rule_engine = rule_engine or RuleEngine()
        self._scorer = scorer or AlertScorer()
        self._incidents = incidents or IncidentCorrelator(window_sec=300)
        self._auto_block_lock = threading.Lock()
        self._auto_block_recent: dict[str, float] = {}
        self._dns_tunnel_state: dict[tuple[str, str], list[datetime]] = defaultdict(list)
        self._tls_no_sni_state: dict[tuple[str, str, int], list[datetime]] = defaultdict(list)
        self._auto_block_stats = {
            "blocked_total": 0,
            "cooldown_skips": 0,
            "whitelist_skips": 0,
            "private_ip_skips": 0,
            "failed_total": 0,
            "last_blocked_at": 0.0,
        }

    def analyze(self, packet: dict[str, Any]) -> list[dict[str, Any]]:
        settings = self._settings_provider()
        packet.update({key: value for key, value in infer_app_protocol(packet).items() if not packet.get(key)})
        raw_alerts: list[dict[str, Any]] = []

        if settings.get("ids_signature_enabled", True):
            try:
                alert = self._ids_sig.analyze_packet(packet)
                if alert:
                    alert["engine"] = "SIG"
                    raw_alerts.append(alert)
            except Exception:
                logger.exception("Signature IDS failed for packet")

        try:
            alert = self._rule_engine.analyze(packet)
            if alert:
                alert["engine"] = "RULE"
                raw_alerts.append(alert)
        except Exception:
            logger.exception("Rule engine failed for packet")

        if settings.get("ids_ml_enabled", True):
            try:
                threshold = float(settings.get("ids_ml_threshold", 0.25) or 0.25)
                alert = self._ids_ml.analyze_packet(packet, threshold=threshold)
                if alert:
                    alert["engine"] = "ML"
                    raw_alerts.append(alert)
            except Exception:
                logger.exception("ML IDS failed for packet")

        try:
            raw_alerts.extend(self._detect_application_alerts(packet))
        except Exception:
            logger.exception("App-aware detection failed for packet")

        alerts = [self._build_alert_payload(packet, alert) for alert in raw_alerts]
        self._maybe_auto_block(settings, alerts)
        return alerts

    def _build_alert_payload(self, packet: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
        try:
            self._scorer.enrich_alert(packet, alert, sig_engine=self._ids_sig)
            self._incidents.enrich_alert(packet, alert)
        except Exception:
            logger.exception("Failed to enrich alert")

        return {
            "ts": packet.get("ts"),
            "src": packet.get("src"),
            "dst": packet.get("dst"),
            "proto": packet.get("proto"),
            "dport": packet.get("dport"),
            "attack_type": alert.get("attack_type") or alert.get("attack") or "Alert",
            "engine": alert.get("engine", ""),
            "severity": alert.get("severity", ""),
            "score_raw": float(alert.get("score_raw", alert.get("score", 0.0)) or 0.0),
            "incident_id": alert.get("incident_id", ""),
            "incident_count": int(alert.get("incident_count", 1) or 1),
            "incident_score": float(alert.get("incident_score", alert.get("score", 0.0)) or 0.0),
            "score": float(alert.get("score", 0.0) or 0.0),
            "detail": alert.get("detail") or packet.get("summary") or "",
            "packet_id": alert.get("packet_id") or packet.get("id"),
            "remote_ip": alert.get("remote_ip") or packet.get("remote_ip"),
            "app_protocol": alert.get("app_protocol") or packet.get("app_protocol"),
            "app_category": alert.get("app_category") or packet.get("app_category"),
            "app_confidence": alert.get("app_confidence") or packet.get("app_confidence"),
            "l7": packet.get("l7"),
            "dns_qname": alert.get("dns_qname") or packet.get("dns_qname"),
            "http_host": alert.get("http_host") or packet.get("http_host"),
            "http_path": alert.get("http_path") or packet.get("http_path"),
            "sni": alert.get("sni") or packet.get("tls_sni") or packet.get("sni"),
        }

    def _detect_application_alerts(self, packet: dict[str, Any]) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc)
        self._cleanup_app_state(now)

        dns_alert = self._detect_dns_tunneling(packet, now)
        if dns_alert:
            alerts.append(dns_alert)

        cleartext_auth_alert = self._detect_cleartext_auth(packet)
        if cleartext_auth_alert:
            alerts.append(cleartext_auth_alert)

        tls_no_sni_alert = self._detect_tls_no_sni(packet, now)
        if tls_no_sni_alert:
            alerts.append(tls_no_sni_alert)

        admin_probe_alert = self._detect_http_admin_probe(packet)
        if admin_probe_alert:
            alerts.append(admin_probe_alert)

        return alerts

    def _detect_dns_tunneling(self, packet: dict[str, Any], now: datetime) -> dict[str, Any] | None:
        if str(packet.get("app_protocol") or "").upper() != "DNS":
            return None
        qname = str(packet.get("dns_qname") or "").strip().strip(".")
        if not qname:
            return None
        labels = [part for part in qname.split(".") if part]
        longest_label = max((len(part) for part in labels), default=0)
        suspicious = len(qname) >= 52 or len(labels) >= 5 or longest_label >= 24 or int(packet.get("dns_qtype") or 0) == 16
        if not suspicious:
            return None
        key = (str(packet.get("src") or "-"), str(packet.get("remote_ip") or packet.get("dst") or "-"))
        samples = self._dns_tunnel_state[key]
        cutoff = now - timedelta(seconds=DNS_TUNNEL_WINDOW_SEC)
        samples[:] = [value for value in samples if value >= cutoff]
        samples.append(now)
        if len(samples) < DNS_TUNNEL_THRESHOLD:
            return None
        return {
            "attack_type": "DNS Tunneling / Exfil Pattern",
            "severity": "high",
            "score": min(0.96, 0.74 + (len(samples) * 0.06)),
            "detail": f"Suspicious DNS query burst for {qname} (labels={len(labels)}, longest_label={longest_label}, count={len(samples)}).",
            "app_protocol": "DNS",
            "app_category": "dns",
            "app_confidence": "high",
            "dns_qname": qname,
        }

    def _detect_cleartext_auth(self, packet: dict[str, Any]) -> dict[str, Any] | None:
        if str(packet.get("app_protocol") or "").upper() != "HTTP":
            return None
        if not self._is_remote_flow(packet):
            return None
        method = str(packet.get("http_method") or "").upper()
        path = str(packet.get("http_path") or "").lower()
        if method not in {"POST", "PUT", "PATCH"}:
            return None
        if not any(token in path for token in ("login", "signin", "auth", "token", "password", "session", "oauth", "wp-login")):
            return None
        host = str(packet.get("http_host") or packet.get("dst") or "-")
        return {
            "attack_type": "Cleartext Auth Over HTTP",
            "severity": "medium",
            "score": 0.74,
            "detail": f"HTTP {method} request to sensitive path {path or '/'} on host {host} crossed a remote boundary without TLS.",
            "app_protocol": "HTTP",
            "app_category": "web",
            "app_confidence": "high",
            "http_host": host,
            "http_path": path or "/",
        }

    def _detect_tls_no_sni(self, packet: dict[str, Any], now: datetime) -> dict[str, Any] | None:
        app_protocol = str(packet.get("app_protocol") or "").upper()
        if app_protocol not in {"TLS", "HTTPS", "QUIC"}:
            return None
        if not self._is_remote_flow(packet):
            return None
        port = self._packet_port(packet)
        if port not in {443, 8443, 9443}:
            return None
        sni = str(packet.get("tls_sni") or packet.get("sni") or "").strip()
        if sni:
            return None
        key = (
            str(packet.get("src") or "-"),
            str(packet.get("remote_ip") or packet.get("dst") or "-"),
            port,
        )
        samples = self._tls_no_sni_state[key]
        cutoff = now - timedelta(seconds=TLS_NO_SNI_WINDOW_SEC)
        samples[:] = [value for value in samples if value >= cutoff]
        samples.append(now)
        if len(samples) < TLS_NO_SNI_THRESHOLD:
            return None
        alpn = list(packet.get("tls_alpn") or packet.get("alpn") or [])
        return {
            "attack_type": "TLS Without SNI / Beacon Pattern",
            "severity": "medium",
            "score": 0.68,
            "detail": f"Repeated {app_protocol} sessions to remote port {port} without SNI were observed (count={len(samples)}, alpn={','.join(map(str, alpn)) or '-'}).",
            "app_protocol": app_protocol,
            "app_category": packet.get("app_category") or "encrypted",
            "app_confidence": packet.get("app_confidence") or "medium",
            "sni": "",
        }

    def _detect_http_admin_probe(self, packet: dict[str, Any]) -> dict[str, Any] | None:
        if str(packet.get("app_protocol") or "").upper() != "HTTP":
            return None
        if str(packet.get("direction") or "").upper() != "INCOMING":
            return None
        path = str(packet.get("http_path") or "").lower()
        if not any(token in path for token in ("/admin", "wp-admin", "phpmyadmin", "/manager", "/console", "/login")):
            return None
        host = str(packet.get("http_host") or packet.get("dst") or "-")
        method = str(packet.get("http_method") or "GET").upper()
        return {
            "attack_type": "Admin Panel Probe",
            "severity": "medium",
            "score": 0.67,
            "detail": f"Incoming HTTP {method} request targeted a likely admin surface {path or '/'} on host {host}.",
            "app_protocol": "HTTP",
            "app_category": "web",
            "app_confidence": "high",
            "http_host": host,
            "http_path": path or "/",
        }

    def _maybe_auto_block(self, settings: dict[str, Any], alerts: list[dict[str, Any]]) -> None:
        if not settings.get("auto_block"):
            return

        whitelist = {
            item.strip()
            for item in str(settings.get("whitelist_ips", "")).split(",")
            if item.strip()
        }

        for alert in alerts:
            ip = alert.get("src")
            if not ip:
                continue
            if ip in whitelist:
                with self._auto_block_lock:
                    self._auto_block_stats["whitelist_skips"] += 1
                continue
            if self._is_private_ip(ip):
                with self._auto_block_lock:
                    self._auto_block_stats["private_ip_skips"] += 1
                continue
            if float(alert.get("score", 0.0)) < AUTO_BLOCK_SCORE_THRESHOLD:
                continue
            if self._cooldown_active(ip):
                continue
            try:
                blocked = block_ip(ip)
                if not blocked:
                    with self._auto_block_lock:
                        self._auto_block_stats["failed_total"] += 1
                    logger.warning("Auto block did not succeed for ip=%s", ip)
                    continue
                self._record_block(ip)
            except Exception:
                with self._auto_block_lock:
                    self._auto_block_stats["failed_total"] += 1
                logger.exception("Auto block failed for ip=%s", ip)

    def stats(self) -> dict[str, int | float]:
        with self._auto_block_lock:
            return dict(self._auto_block_stats)

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        return is_local_ip(ip)

    def _cooldown_active(self, ip: str) -> bool:
        now = time.time()
        with self._auto_block_lock:
            previous = self._auto_block_recent.get(ip)
            if previous is None or (now - previous) >= AUTO_BLOCK_COOLDOWN_SEC:
                return False
            self._auto_block_stats["cooldown_skips"] += 1
            return True

    def _record_block(self, ip: str) -> None:
        now = time.time()
        with self._auto_block_lock:
            self._auto_block_recent[ip] = now
            self._auto_block_stats["blocked_total"] += 1
            self._auto_block_stats["last_blocked_at"] = now
            if len(self._auto_block_recent) > AUTO_BLOCK_MAX_TRACKED:
                expired = sorted(self._auto_block_recent.items(), key=lambda item: item[1])[: len(self._auto_block_recent) - AUTO_BLOCK_MAX_TRACKED]
                for old_ip, _ in expired:
                    self._auto_block_recent.pop(old_ip, None)

    def _cleanup_app_state(self, now: datetime) -> None:
        self._prune_state(self._dns_tunnel_state, now - timedelta(seconds=DNS_TUNNEL_WINDOW_SEC))
        self._prune_state(self._tls_no_sni_state, now - timedelta(seconds=TLS_NO_SNI_WINDOW_SEC))

    @staticmethod
    def _prune_state(bucket: dict[Any, list[datetime]], cutoff: datetime) -> None:
        for key, values in list(bucket.items()):
            values[:] = [value for value in values if value >= cutoff]
            if not values:
                bucket.pop(key, None)
        if len(bucket) > MAX_APP_TRACKED_KEYS:
            overflow = len(bucket) - MAX_APP_TRACKED_KEYS
            for key in list(bucket.keys())[:overflow]:
                bucket.pop(key, None)

    @staticmethod
    def _packet_port(packet: dict[str, Any]) -> int:
        for field in ("dport", "sport"):
            try:
                value = int(packet.get(field) or 0)
            except (TypeError, ValueError):
                value = 0
            if value > 0:
                return value
        return 0

    def _is_remote_flow(self, packet: dict[str, Any]) -> bool:
        remote_ip = str(packet.get("remote_ip") or "").strip()
        if remote_ip:
            return is_remote_ip(remote_ip)
        src = str(packet.get("src") or "").strip()
        dst = str(packet.get("dst") or "").strip()
        return bool((src and is_remote_ip(src)) or (dst and is_remote_ip(dst)))
