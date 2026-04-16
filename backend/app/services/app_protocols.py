from __future__ import annotations

import math
from typing import Any


_PORT_PROTOCOLS: dict[int, tuple[str, str]] = {
    20: ("FTP-DATA", "file-transfer"),
    21: ("FTP", "file-transfer"),
    22: ("SSH", "remote-access"),
    25: ("SMTP", "email"),
    53: ("DNS", "dns"),
    80: ("HTTP", "web"),
    88: ("KERBEROS", "identity"),
    110: ("POP3", "email"),
    119: ("NNTP", "email"),
    123: ("NTP", "infra"),
    135: ("MSRPC", "infra"),
    139: ("SMB", "file-share"),
    143: ("IMAP", "email"),
    389: ("LDAP", "directory"),
    443: ("HTTPS", "web"),
    445: ("SMB", "file-share"),
    465: ("SMTPS", "email"),
    500: ("IKE / ISAKMP", "vpn"),
    587: ("SMTP", "email"),
    636: ("LDAPS", "directory"),
    853: ("DNS-over-TLS", "dns"),
    993: ("IMAPS", "email"),
    995: ("POP3S", "email"),
    1194: ("OpenVPN", "vpn"),
    1433: ("MSSQL", "database"),
    1521: ("ORACLE", "database"),
    1701: ("L2TP", "vpn"),
    3306: ("MYSQL", "database"),
    3389: ("RDP", "remote-access"),
    3478: ("STUN / TURN", "traversal"),
    5004: ("RTP", "media"),
    5060: ("SIP", "voice"),
    5061: ("SIPS", "voice"),
    51820: ("WireGuard", "vpn"),
    5432: ("POSTGRES", "database"),
    5900: ("VNC", "remote-access"),
    6379: ("REDIS", "database"),
    8080: ("HTTP", "web"),
    8443: ("HTTPS", "web"),
    9200: ("ELASTIC", "infra"),
    9443: ("HTTPS", "web"),
}

_STANDARD_PORTS: dict[str, set[int]] = {
    "DNS": {53, 5353, 853},
    "DNS-over-TLS": {853},
    "HTTP": {80, 8000, 8080, 8081, 3000, 5000, 8008, 8888},
    "HTTPS": {443, 8443, 9443},
    "TLS": {443, 465, 563, 636, 853, 989, 990, 992, 993, 995, 8443, 9443},
    "QUIC": {443, 784, 853},
    "IPsec NAT-T": {4500},
    "IKE / ISAKMP": {500},
    "WireGuard": {51820},
    "OpenVPN": {1194},
    "L2TP": {1701},
    "STUN / TURN": {3478, 5349},
}

_HTTP_METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"}


def _normalize_alpn(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _port_candidates(packet: dict[str, Any]) -> list[int]:
    ports: list[int] = []
    for field in ("dport", "sport"):
        value = _safe_int(packet.get(field))
        if value and value > 0:
            ports.append(value)
    return ports


def _service_port(packet: dict[str, Any]) -> int | None:
    direction = _normalize_text(packet.get("direction")).upper()
    if direction == "OUTGOING":
        return _safe_int(packet.get("dport")) or _safe_int(packet.get("sport"))
    if direction == "INCOMING":
        return _safe_int(packet.get("sport")) or _safe_int(packet.get("dport"))
    return _safe_int(packet.get("dport")) or _safe_int(packet.get("sport"))


def _primary_port_hint(ports: list[int]) -> tuple[str, str] | None:
    for port in ports:
        mapped = _PORT_PROTOCOLS.get(port)
        if mapped:
            return mapped
    return None


def _confidence_label(score: float) -> str:
    if score >= 0.82:
        return "high"
    if score >= 0.56:
        return "medium"
    return "low"


def _decode_payload(packet: dict[str, Any]) -> bytes:
    hex_text = _normalize_text(packet.get("payload_hex"))
    if not hex_text:
        return b""
    pieces = "".join(part for part in hex_text.split() if part)
    if len(pieces) < 2:
        return b""
    try:
        return bytes.fromhex(pieces)
    except ValueError:
        return b""


def _payload_metrics(packet: dict[str, Any]) -> dict[str, Any]:
    payload = _decode_payload(packet)
    if not payload:
        return {
            "payload_bytes": b"",
            "payload_binary_like": False,
            "payload_entropy": 0.0,
            "payload_printable_ratio": 0.0,
        }

    counts: dict[int, int] = {}
    printable = 0
    for byte in payload:
        counts[byte] = counts.get(byte, 0) + 1
        if 32 <= byte < 127:
            printable += 1
    entropy = 0.0
    total = len(payload)
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    printable_ratio = printable / total if total else 0.0
    binary_like = printable_ratio < 0.45 or entropy >= 4.3
    return {
        "payload_bytes": payload,
        "payload_binary_like": binary_like,
        "payload_entropy": round(entropy, 2),
        "payload_printable_ratio": round(printable_ratio, 2),
    }


def _looks_like_quic(payload: bytes) -> bool:
    if len(payload) < 6:
        return False
    first = payload[0]
    if (first & 0xC0) != 0xC0:
        return False
    version = int.from_bytes(payload[1:5], byteorder="big", signed=False)
    return version > 0


def _looks_like_nat_t(payload: bytes) -> bool:
    return len(payload) >= 4 and payload[:4] == b"\x00\x00\x00\x00"


def _looks_like_stun(payload: bytes) -> bool:
    return len(payload) >= 20 and payload[4:8] == b"\x21\x12\xa4\x42"


def _dns_tunnel_like(packet: dict[str, Any]) -> bool:
    qname = _normalize_text(packet.get("dns_qname")).strip(".")
    if not qname:
        return False
    labels = [label for label in qname.split(".") if label]
    longest_label = max((len(label) for label in labels), default=0)
    qtype = _safe_int(packet.get("dns_qtype")) or 0
    return len(qname) >= 52 or len(labels) >= 5 or longest_label >= 24 or qtype == 16


def infer_app_protocol(packet: dict[str, Any]) -> dict[str, Any]:
    l7 = _normalize_text(packet.get("l7"))
    l7_upper = l7.upper()
    proto = _normalize_text(packet.get("proto")).upper() or "OTHER"
    tls_sni = _normalize_text(packet.get("tls_sni") or packet.get("sni"))
    tls_version = _normalize_text(packet.get("tls_version"))
    tls_alpn = _normalize_alpn(packet.get("tls_alpn") or packet.get("alpn"))
    http_method = _normalize_text(packet.get("http_method")).upper()
    http_host = _normalize_text(packet.get("http_host"))
    http_status = _safe_int(packet.get("http_status"))
    dns_qname = _normalize_text(packet.get("dns_qname"))
    ports = _port_candidates(packet)
    service_port = _service_port(packet)
    payload = _payload_metrics(packet)
    payload_bytes = payload["payload_bytes"]
    payload_binary_like = bool(payload["payload_binary_like"])

    app_protocol = ""
    app_category = "unknown"
    confidence_score = 0.24
    basis: list[str] = []
    notes: list[str] = []
    handshake = ""

    port_hint = _primary_port_hint(ports)
    if port_hint:
        basis.append(f"Port hint: {port_hint[0]}")
        confidence_score = max(confidence_score, 0.42)

    if dns_qname or l7_upper.startswith("DNS "):
        app_protocol = "DNS"
        app_category = "dns"
        confidence_score = 0.93
        handshake = "DNS question"
        basis.append("Payload decode: DNS question")
        if _dns_tunnel_like(packet):
            notes.append("DNS query shape looks tunnel-like or unusually long.")

    elif http_method in _HTTP_METHODS or http_host or l7_upper.startswith("HTTP "):
        app_protocol = "HTTP"
        app_category = "web"
        confidence_score = 0.91
        handshake = "HTTP request"
        basis.append("Payload decode: HTTP request line")
    elif http_status is not None or l7_upper.startswith("HTTP RESPONSE"):
        app_protocol = "HTTP"
        app_category = "web"
        confidence_score = 0.89
        handshake = "HTTP response"
        basis.append("Payload decode: HTTP response")

    elif proto == "UDP" and any(item.lower().startswith("h3") for item in tls_alpn):
        app_protocol = "QUIC"
        app_category = "web"
        confidence_score = 0.9
        handshake = "QUIC ALPN hint"
        basis.append("ALPN indicates HTTP/3 over UDP")
    elif proto == "UDP" and _looks_like_quic(payload_bytes):
        app_protocol = "QUIC"
        app_category = "web"
        confidence_score = 0.84
        handshake = "QUIC long-header candidate"
        basis.append("Payload looks like a QUIC long header")

    elif tls_version or tls_sni or tls_alpn or l7_upper == "TLS" or _normalize_text(packet.get("ja3")) or _normalize_text(packet.get("ja4")):
        app_category = "encrypted"
        confidence_score = 0.78
        handshake = "TLS ClientHello"
        if tls_version:
            basis.append(f"TLS handshake: {tls_version}")
            confidence_score = max(confidence_score, 0.86)
        elif _normalize_text(packet.get("ja3")) or _normalize_text(packet.get("ja4")):
            basis.append("TLS fingerprint metadata present")
            confidence_score = max(confidence_score, 0.82)
        else:
            basis.append("TLS metadata present")
        if any(item.lower().startswith("h2") or item.lower().startswith("http/1") for item in tls_alpn):
            app_protocol = "HTTPS"
            app_category = "web"
            confidence_score = max(confidence_score, 0.9)
            basis.append("ALPN matches web TLS")
        elif service_port in {443, 8443, 9443}:
            app_protocol = "HTTPS"
            app_category = "web"
            confidence_score = max(confidence_score, 0.88)
        elif service_port == 853:
            app_protocol = "DNS-over-TLS"
            app_category = "dns"
            confidence_score = max(confidence_score, 0.86)
            notes.append("TLS metadata on port 853 suggests DNS over TLS.")
        else:
            app_protocol = "TLS"

    elif proto == "UDP" and service_port == 4500:
        app_protocol = "IPsec NAT-T"
        app_category = "vpn"
        confidence_score = 0.79
        handshake = "NAT-T tunnel candidate"
        basis.append("Port hint: UDP/4500")
        if _looks_like_nat_t(payload_bytes):
            confidence_score = 0.91
            payload_binary_like = True
            basis.append("Non-ESP marker present")
            notes.append("Payload starts with a Non-ESP marker, which strengthens the NAT-T interpretation.")
        elif payload["payload_binary_like"]:
            notes.append("Binary payload preview supports an encrypted tunnel interpretation.")

    elif proto == "UDP" and service_port == 500:
        app_protocol = "IKE / ISAKMP"
        app_category = "vpn"
        confidence_score = 0.84
        handshake = "IKE negotiation candidate"
        basis.append("Port hint: UDP/500")

    elif proto == "UDP" and service_port == 51820:
        app_protocol = "WireGuard"
        app_category = "vpn"
        confidence_score = 0.86
        handshake = "WireGuard candidate"
        basis.append("Port hint: UDP/51820")

    elif proto == "UDP" and (service_port in {3478, 5349} or _looks_like_stun(payload_bytes)):
        app_protocol = "STUN / TURN"
        app_category = "traversal"
        confidence_score = 0.8
        handshake = "STUN transaction"
        if _looks_like_stun(payload_bytes):
            basis.append("STUN magic cookie present")
            confidence_score = 0.88
        else:
            basis.append("Port hint: STUN / TURN")

    if not app_protocol and port_hint:
        app_protocol, app_category = port_hint
        confidence_score = max(confidence_score, 0.52)

    if not app_protocol:
        app_protocol = proto

    standard_ports = _STANDARD_PORTS.get(app_protocol, set())
    unusual_port = bool(service_port and standard_ports and service_port not in standard_ports)
    if unusual_port:
        basis.append(f"Observed on unusual port {service_port}")
        notes.append(f"{app_protocol} metadata was observed on non-standard port {service_port}.")
        confidence_score = max(confidence_score, 0.76 if app_protocol in {"HTTP", "HTTPS", "TLS", "DNS", "QUIC"} else confidence_score)

    if payload_binary_like and app_protocol in {"TLS", "HTTPS", "QUIC", "IPsec NAT-T", "WireGuard", "OpenVPN"}:
        notes.append("Payload preview looks binary or encrypted.")

    if not handshake and port_hint:
        handshake = f"Port-based {port_hint[0]} hint"

    protocol_notes = " ".join(dict.fromkeys(note for note in notes if note))
    protocol_basis = " | ".join(dict.fromkeys(item for item in basis if item))

    return {
        "app_protocol": app_protocol,
        "app_category": app_category,
        "app_confidence": _confidence_label(confidence_score),
        "protocol_basis": protocol_basis,
        "protocol_notes": protocol_notes,
        "protocol_handshake": handshake,
        "protocol_unusual_port": unusual_port,
        "payload_binary_like": payload_binary_like,
        "payload_entropy": payload["payload_entropy"],
        "payload_printable_ratio": payload["payload_printable_ratio"],
    }
