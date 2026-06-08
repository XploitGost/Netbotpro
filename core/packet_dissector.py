from __future__ import annotations

import re
from typing import Any

from core.expert_info import packet_expert_items
from core.flow_engine import flow_id_for
from core.privacy_redaction import redact_sensitive_data, redact_sensitive_text


def _field(label: str, key: str, value: Any, description: str = "", byte_range: list[int] | None = None, severity: str = "info") -> dict[str, Any]:
    display = redact_sensitive_text(str(value if value is not None else "-"))
    return {"label": label, "key": key, "value": display, "display_value": display, "raw_value": "", "description": description, "byte_range": byte_range or [], "severity": severity, "children": []}


def _layer(name: str, summary: str, fields: list[dict[str, Any]]) -> dict[str, Any]:
    return {"name": name, "summary": redact_sensitive_text(summary), "fields": fields}


def _hex_view(packet: dict[str, Any], capture_mode: str) -> dict[str, Any]:
    raw_hex = re.sub(r"[^0-9a-fA-F]", "", str(packet.get("payload_hex") or ""))
    if capture_mode == "metadata":
        raw_hex = ""
    raw_hex = raw_hex[:1024]
    rows = []
    for offset in range(0, len(raw_hex), 32):
        chunk = raw_hex[offset:offset + 32]
        octets = [chunk[index:index + 2] for index in range(0, len(chunk), 2)]
        decoded = "".join(chr(int(item, 16)) if 32 <= int(item, 16) <= 126 else "." for item in octets)
        rows.append({"offset": f"{offset // 2:04x}", "hex": " ".join(octets), "ascii": "[REDACTED]", "ascii_redacted": redact_sensitive_text(decoded)})
    return {
        "rows": rows,
        "truncated": len(str(packet.get("payload_hex") or "")) > 1024,
        "mode": "headers_only" if capture_mode == "metadata" else "redacted_preview",
        "ascii_redacted": True,
        "warning": "Raw bytes may contain sensitive data; ASCII is always redacted." if capture_mode != "metadata" else "Metadata mode does not expose raw payload bytes.",
    }


def dissect_packet(packet: dict[str, Any], *, capture_mode: str = "metadata", related_alert_ids: list[str] | None = None) -> dict[str, Any]:
    packet = redact_sensitive_data(packet)
    proto = str(packet.get("proto") or "OTHER").upper()
    app = str(packet.get("app_protocol") or "").upper()
    layers = [_layer("Frame", f"{packet.get('length') or 0} bytes on wire", [
        _field("Timestamp", "frame.timestamp", packet.get("ts") or packet.get("timestamp")),
        _field("Frame Length", "frame.length", packet.get("length") or 0, byte_range=[0, 0]),
        _field("Interface", "frame.interface", packet.get("interface") or "default"),
        _field("Direction", "frame.direction", str(packet.get("direction") or "unknown").lower()),
    ])]
    if packet.get("src_mac") or packet.get("dst_mac"):
        layers.append(_layer("Ethernet", f"{packet.get('src_mac') or '-'} -> {packet.get('dst_mac') or '-'}", [
            _field("Source MAC", "eth.src", packet.get("src_mac"), byte_range=[6, 12]),
            _field("Destination MAC", "eth.dst", packet.get("dst_mac"), byte_range=[0, 6]),
            _field("EtherType", "eth.type", "IPv4/IPv6"),
        ]))
    if packet.get("arp_operation") is not None:
        layers.append(_layer("ARP", f"{packet.get('arp_sender_ip') or '-'} -> {packet.get('arp_target_ip') or '-'}", [
            _field("Operation", "arp.operation", packet.get("arp_operation")),
            _field("Sender MAC", "arp.sender_mac", packet.get("arp_sender_mac")),
            _field("Sender IP", "arp.sender_ip", packet.get("arp_sender_ip")),
            _field("Target MAC", "arp.target_mac", packet.get("arp_target_mac")),
            _field("Target IP", "arp.target_ip", packet.get("arp_target_ip")),
        ]))
    if packet.get("src") or packet.get("dst"):
        ip_name = "IPv6" if ":" in str(packet.get("src") or packet.get("dst") or "") else "IPv4"
        layers.append(_layer(ip_name, f"{packet.get('src') or '-'} -> {packet.get('dst') or '-'}", [
            _field("Version", "ip.version", 6 if ip_name == "IPv6" else 4),
            _field("Source IP", "ip.src", packet.get("src"), byte_range=[26, 30] if ip_name == "IPv4" else []),
            _field("Destination IP", "ip.dst", packet.get("dst"), byte_range=[30, 34] if ip_name == "IPv4" else []),
            _field("TTL / Hop Limit", "ip.ttl", packet.get("ttl")),
            _field("Protocol", "ip.protocol", proto),
            _field("Traffic Class", "ipv6.traffic_class", packet.get("traffic_class")),
            _field("Flow Label", "ipv6.flow_label", packet.get("flow_label")),
            _field("Flags", "ip.flags", packet.get("ip_flags") or packet.get("flags")),
            _field("Fragment Offset", "ip.fragment_offset", packet.get("fragment_offset") or 0),
        ]))
    if proto in {"TCP", "UDP", "ICMP"}:
        fields = [_field("Source Port", f"{proto.lower()}.src_port", packet.get("sport")), _field("Destination Port", f"{proto.lower()}.dst_port", packet.get("dport"))]
        if proto == "TCP":
            fields += [_field("Flags", "tcp.flags", packet.get("flags")), _field("Sequence", "tcp.seq", packet.get("seq")), _field("Acknowledgment", "tcp.ack", packet.get("ack")), _field("Window", "tcp.window", packet.get("window")), _field("Payload Length", "tcp.payload_length", packet.get("payload_length") or 0)]
        elif proto == "UDP":
            fields += [_field("Length", "udp.length", packet.get("udp_length") or packet.get("length"))]
        else:
            fields += [_field("Type", "icmp.type", packet.get("icmp_type")), _field("Code", "icmp.code", packet.get("icmp_code"))]
        layers.append(_layer(proto, f"{packet.get('sport') or '-'} -> {packet.get('dport') or '-'}", fields))
    if app:
        safe_keys = {
            "DNS": ["dns_query", "dns_query_type", "dns_rcode", "dns_answer_count"],
            "HTTP": ["http_method", "http_host", "http_path", "http_status", "user_agent", "content_type", "content_length"],
            "TLS": ["tls_version", "tls_record_type", "tls_handshake_type", "tls_sni", "tls_alpn", "tls_cipher_suite"],
        }.get(app, ["banner", "protocol_guess_reason"])
        layers.append(_layer(app, str(packet.get("summary") or app), [_field(key.replace("_", " ").title(), key.replace("_", "."), packet.get(key)) for key in safe_keys if packet.get(key) is not None]))
    flow_id = flow_id_for(packet)
    result = {
        "packet_id": packet.get("id"),
        "timestamp": packet.get("ts") or packet.get("timestamp"),
        "length": int(packet.get("length") or 0),
        "captured_length": int(packet.get("captured_length") or packet.get("length") or 0),
        "interface": packet.get("interface") or "default",
        "direction": str(packet.get("direction") or "unknown").lower(),
        "protocol_stack": [item["name"] for item in layers],
        "summary": redact_sensitive_text(str(packet.get("summary") or "")),
        "layers": layers,
        "hex": _hex_view(packet, capture_mode),
        "related_flow_id": flow_id,
        "related_alert_ids": related_alert_ids or [],
        "expert_items": packet_expert_items(packet, flow_id),
    }
    return redact_sensitive_data(result)
