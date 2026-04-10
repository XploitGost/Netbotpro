from __future__ import annotations

import ipaddress
import logging
import threading
import time
from typing import Any, Callable

from backend.app.bootstrap import ensure_project_root_on_path

ensure_project_root_on_path()

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
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

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
