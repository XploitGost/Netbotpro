from __future__ import annotations

from typing import Any

_ALERT_WEIGHTS = {"critical": 34, "high": 20, "medium": 10, "low": 3}
_COMMON_PROTOCOLS = {"DNS", "HTTP", "TLS", "SSH", "ICMP"}
_SENSITIVE_PROCESSES = {"powershell", "cmd", "wscript", "cscript", "rundll32"}


def risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def score_flow(flow: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []
    alerts = flow.get("alert_counts") or {}
    for severity, weight in _ALERT_WEIGHTS.items():
        count = int(alerts.get(severity, 0) or 0)
        if count:
            score += min(weight * count, weight * 2)
    if int(alerts.get("critical", 0) or 0) or int(alerts.get("high", 0) or 0):
        score += 10
        reasons.append("High alert density on this flow")

    protocol = str(flow.get("app_protocol") or "UNKNOWN").upper()
    direction = str(flow.get("direction") or "").lower()
    metadata = flow.get("metadata") or {}
    if protocol == "UNKNOWN" and direction in {"inbound", "outbound"}:
        score += 22
        reasons.append("Unknown protocol on an external connection")
    elif protocol not in _COMMON_PROTOCOLS and direction == "outbound":
        score += 9
        reasons.append("Uncommon outbound protocol")

    if bool(flow.get("protocol_unusual_port")):
        score += 14
        reasons.append("Protocol observed on an unusual port")
    if int(flow.get("packets_count", 0) or 0) >= 1000:
        score += 12
        reasons.append("High packet rate")
    if int(flow.get("bytes_total", 0) or 0) >= 50 * 1024 * 1024:
        score += 12
        reasons.append("High byte volume")
    if int(flow.get("dns_failures", 0) or 0) >= 3:
        score += 20
        reasons.append("Repeated DNS failures")
    if direction == "outbound" and flow.get("new_destination"):
        score += 10
        if protocol == "TLS" and metadata.get("sni"):
            reasons.append("External TLS connection with new SNI")
        else:
            reasons.append("Unusual outbound destination")

    process = str(flow.get("process_name") or "").lower()
    if direction == "outbound" and any(name in process for name in _SENSITIVE_PROCESSES):
        score += 18
        reasons.append("External connection from a sensitive process")

    bounded = max(0, min(100, score))
    if not reasons:
        reasons.append("No material risk indicators observed")
    return {"score": bounded, "level": risk_level(bounded), "reasons": reasons}


__all__ = ["risk_level", "score_flow"]
