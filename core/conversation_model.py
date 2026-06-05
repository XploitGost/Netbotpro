from __future__ import annotations

import hashlib
from typing import Any


def conversation_id_for(packet: dict[str, Any]) -> str:
    left = (str(packet.get("src") or "-"), int(packet.get("sport") or 0))
    right = (str(packet.get("dst") or "-"), int(packet.get("dport") or 0))
    endpoints = sorted((left, right))
    transport = str(packet.get("proto") or "OTHER").upper()
    raw = f"{endpoints[0]}|{endpoints[1]}|{transport}"
    return f"conv-{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def timeline_event(
    timestamp: str,
    event_type: str,
    summary: str,
    *,
    severity: str = "info",
    metadata: dict[str, Any] | None = None,
    related_packet_id: str | None = None,
    related_alert_id: str | None = None,
) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "summary": summary,
        "severity": severity,
        "metadata": metadata or {},
        "related_packet_id": related_packet_id,
        "related_alert_id": related_alert_id,
    }


__all__ = ["conversation_id_for", "timeline_event"]
