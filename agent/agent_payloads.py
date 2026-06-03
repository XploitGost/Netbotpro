from __future__ import annotations

from typing import Any

from agent.agent_health import collect_health, collect_network
from core.privacy_redaction import redact_sensitive_text


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            key_text = str(key)
            if any(
                marker in key_text.lower()
                for marker in (
                    "api_key",
                    "apikey",
                    "token",
                    "secret",
                    "password",
                    "credential",
                    "cookie",
                    "authorization",
                    "session",
                )
            ):
                cleaned[key_text] = "[REDACTED]"
            else:
                cleaned[key_text] = _redact_value(item)
        return cleaned
    if isinstance(value, list):
        return [_redact_value(item) for item in value[:100]]
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value


def redacted_payload(value: dict[str, Any]) -> dict[str, Any]:
    return _redact_value(value)


def build_telemetry_payload(
    agent_id: str,
    *,
    capture_state: dict[str, Any] | None = None,
    recent_alerts: list[dict[str, Any]] | None = None,
    flow_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    capture_state = capture_state or {}
    recent_alerts = recent_alerts or []
    alerts_by_level = {
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
    }
    for alert in recent_alerts:
        level = str(alert.get("severity") or alert.get("level") or "").lower()
        if level in {"critical", "high", "medium", "low"}:
            alerts_by_level[f"{level}_count"] += 1
    payload = {
        "agent_id": agent_id,
        "health": collect_health(),
        "network": collect_network(),
        "capture": {
            "capture_running": bool(capture_state.get("running")),
            "capture_interface": capture_state.get("iface")
            or capture_state.get("interface")
            or "",
            "capture_mode": capture_state.get("capture_mode") or "metadata",
            "packet_count": int(
                capture_state.get("packet_count")
                or capture_state.get("total_packets")
                or 0
            ),
            "alert_count": int(
                capture_state.get("alert_count")
                or capture_state.get("total_alerts")
                or 0
            ),
            "last_capture_error": capture_state.get("last_capture_error") or "",
        },
        "alerts_summary": {
            "total_alerts": len(recent_alerts),
            **alerts_by_level,
            "recent_alerts": recent_alerts[:10],
        },
        "flows_summary": flow_summary
        or {
            "top_sources": [],
            "top_destinations": [],
            "top_ports": [],
            "protocol_counts": {},
        },
    }
    return redacted_payload(payload)
