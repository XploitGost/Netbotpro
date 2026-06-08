from __future__ import annotations

from typing import Any

from core.privacy_redaction import redact_sensitive_data, redact_sensitive_text


def packet_expert_items(
    packet: dict[str, Any], flow_id: str = ""
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def add(
        severity: str,
        category: str,
        message: str,
        evidence: dict[str, Any] | None = None,
        recommended_action: str = "Review the related packet and flow context.",
    ) -> None:
        items.append(
            {
                "id": f"{category}-{packet.get('id') or len(items) + 1}",
                "severity": severity,
                "category": category,
                "title": message,
                "message": redact_sensitive_text(message),
                "evidence": redact_sensitive_data(evidence or {}),
                "affected_packet_count": 1,
                "related_packet_id": packet.get("id"),
                "related_flow_id": flow_id or None,
                "recommended_action": recommended_action,
                "first_seen": packet.get("ts") or packet.get("timestamp"),
                "last_seen": packet.get("ts") or packet.get("timestamp"),
            }
        )

    flags = str(packet.get("flags") or "").upper()
    app = str(packet.get("app_protocol") or "").upper()
    port = int(packet.get("dport") or 0)
    if "R" in flags:
        add(
            "warn",
            "tcp",
            "TCP reset observed",
            {"flags": flags},
            "Review flow termination and reset frequency.",
        )
    if packet.get("fragment_offset") or "MF" in flags:
        add("warn", "malformed", "Fragmented IP packet observed")
    if app == "DNS" and str(packet.get("dns_rcode") or "").upper() in {"3", "NXDOMAIN"}:
        add("warn", "dns", "DNS NXDOMAIN response observed")
    status = int(packet.get("http_status") or packet.get("status_code") or 0)
    if status >= 400:
        add(
            "warn" if status < 500 else "error",
            "http",
            f"HTTP {status} response observed",
        )
    if app == "HTTP" and str(packet.get("direction") or "").upper() == "OUTGOING":
        add(
            "warn",
            "security",
            "Cleartext HTTP to an external destination",
            recommended_action="Prefer TLS for external application traffic.",
        )
    tls_version = str(packet.get("tls_version") or "").upper()
    if tls_version in {"TLS 1.0", "TLS 1.1", "TLSV1", "TLSV1.1"}:
        add(
            "warn",
            "tls",
            "Deprecated TLS version observed",
            {"version": tls_version},
            "Upgrade the endpoint TLS policy.",
        )
    if port and port not in {22, 25, 53, 80, 110, 143, 443, 445, 3389, 587, 993, 995}:
        add("note", "security", "Uncommon destination port", {"port": port})
    if app == "UNKNOWN" and port in {22, 25, 53, 80, 443, 445, 3389}:
        add(
            "warn",
            "security",
            "Unknown protocol on a common service port",
            {"port": port},
        )
    return items


def flow_expert_items(flow: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def add(severity: str, message: str, evidence: dict[str, Any], action: str) -> None:
        items.append(
            {
                "id": f"flow-{flow.get('flow_id')}-{len(items) + 1}",
                "severity": severity,
                "category": "flow",
                "title": message,
                "message": message,
                "evidence": redact_sensitive_data(evidence),
                "affected_packet_count": int(flow.get("packets_count") or 0),
                "related_flow_id": flow.get("flow_id"),
                "related_packet_id": None,
                "recommended_action": action,
                "first_seen": flow.get("first_seen"),
                "last_seen": flow.get("last_seen"),
            }
        )

    packets, total_bytes = int(flow.get("packets_count") or 0), int(
        flow.get("bytes_total") or 0
    )
    if packets >= 1000:
        add(
            "warn",
            "High packet volume",
            {"packets": packets},
            "Validate whether the traffic volume is expected.",
        )
    if total_bytes >= 10_000_000:
        add(
            "warn",
            "High byte volume",
            {"bytes": total_bytes},
            "Review the destination and transfer context.",
        )
    if len(flow.get("related_alert_ids") or []) >= 3:
        add(
            "error",
            "High alert density on this flow",
            {"alerts": len(flow.get("related_alert_ids") or [])},
            "Prioritize this flow for investigation.",
        )
    if str(flow.get("app_protocol") or "").upper() == "UNKNOWN":
        add(
            "warn",
            "Uncommon or unknown protocol",
            {},
            "Validate the service and destination.",
        )
    return items
