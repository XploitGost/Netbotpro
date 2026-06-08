from __future__ import annotations

from typing import Any

from core.privacy_redaction import redact_sensitive_data


def packet_expert_items(packet: dict[str, Any], flow_id: str = "") -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def add(severity: str, category: str, message: str, evidence: dict[str, Any] | None = None) -> None:
        items.append({
            "severity": severity,
            "category": category,
            "message": message,
            "evidence": redact_sensitive_data(evidence or {}),
            "related_packet_id": packet.get("id"),
            "related_flow_id": flow_id or None,
        })

    flags = str(packet.get("flags") or "").upper()
    app = str(packet.get("app_protocol") or "").upper()
    port = int(packet.get("dport") or 0)
    if "R" in flags:
        add("warn", "tcp", "TCP reset observed", {"flags": flags})
    if packet.get("fragment_offset") or "MF" in flags:
        add("warn", "malformed", "Fragmented IP packet observed")
    if app == "DNS" and str(packet.get("dns_rcode") or "").upper() in {"3", "NXDOMAIN"}:
        add("warn", "dns", "DNS NXDOMAIN response observed")
    status = int(packet.get("http_status") or packet.get("status_code") or 0)
    if status >= 400:
        add("warn" if status < 500 else "error", "http", f"HTTP {status} response observed")
    if app == "HTTP" and str(packet.get("direction") or "").upper() == "OUTGOING":
        add("warn", "security", "Cleartext HTTP to an external destination")
    if port and port not in {22, 25, 53, 80, 110, 143, 443, 445, 3389, 587, 993, 995}:
        add("note", "security", "Uncommon destination port", {"port": port})
    if app == "UNKNOWN" and port in {22, 25, 53, 80, 443, 445, 3389}:
        add("warn", "security", "Unknown protocol on a common service port", {"port": port})
    return items

def flow_expert_items(flow: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def add(severity: str, message: str, evidence: dict[str, Any]) -> None:
        items.append({
            "severity": severity,
            "category": "flow",
            "message": message,
            "evidence": redact_sensitive_data(evidence),
            "related_flow_id": flow.get("flow_id"),
            "related_packet_id": None,
        })

    packets, total_bytes = int(flow.get("packets_count") or 0), int(flow.get("bytes_total") or 0)
    if packets >= 1000:
        add("warn", "High packet volume", {"packets": packets})
    if total_bytes >= 10_000_000:
        add("warn", "High byte volume", {"bytes": total_bytes})
    if len(flow.get("related_alert_ids") or []) >= 3:
        add("error", "High alert density on this flow", {"alerts": len(flow.get("related_alert_ids") or [])})
    if str(flow.get("app_protocol") or "").upper() == "UNKNOWN":
        add("warn", "Uncommon or unknown protocol", {})
    return items
