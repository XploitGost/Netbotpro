from __future__ import annotations

from typing import Any

from core.privacy_redaction import redact_http_path, redact_sensitive_text

_PORT_PROTOCOLS = {
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "SMB",
    143: "IMAP",
    443: "TLS",
    445: "SMB",
    465: "SMTP",
    587: "SMTP",
    993: "IMAP",
    995: "POP3",
    3389: "RDP",
    8080: "HTTP",
    8443: "TLS",
}

_SAFE_METADATA_FIELDS = (
    "dns_qname",
    "dns_qtype",
    "dns_rcode",
    "dns_answer_count",
    "http_method",
    "http_host",
    "http_path",
    "http_status",
    "http_user_agent",
    "http_content_type",
    "tls_sni",
    "sni",
    "tls_alpn",
    "alpn",
    "tls_version",
    "certificate_subject",
    "certificate_issuer",
    "certificate_not_before",
    "certificate_not_after",
    "protocol_basis",
    "protocol_notes",
    "protocol_handshake",
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _port(packet: dict[str, Any]) -> int:
    for key in ("dport", "sport"):
        try:
            value = int(packet.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value in _PORT_PROTOCOLS:
            return value
    try:
        return int(packet.get("dport") or packet.get("sport") or 0)
    except (TypeError, ValueError):
        return 0


def _signature_protocol(packet: dict[str, Any]) -> str:
    payload = _text(packet.get("payload_ascii")).upper()
    if payload.startswith("SSH-"):
        return "SSH"
    if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "HTTP/")):
        return "HTTP"
    if payload.startswith(("220 ", "EHLO ", "HELO ")):
        return "SMTP"
    if payload.startswith(("+OK", "-ERR")):
        return "POP3"
    if payload.startswith(("* OK", "* PREAUTH")):
        return "IMAP"
    if payload.startswith("\u0003\u0000") or "COOKIE: MSTSHASH=" in payload:
        return "RDP"
    if payload.startswith("\u00ffSMB") or payload.startswith("\u00feSMB"):
        return "SMB"
    return ""


def _normalize_protocol(value: Any) -> str:
    protocol = _text(value).upper()
    if protocol in {"HTTPS", "DNS-OVER-TLS", "SMTPS", "IMAPS", "POP3S"}:
        return "TLS"
    if protocol in {
        "DNS",
        "HTTP",
        "TLS",
        "SSH",
        "RDP",
        "SMB",
        "SMTP",
        "IMAP",
        "POP3",
        "ICMP",
    }:
        return protocol
    return ""


def _safe_metadata(packet: dict[str, Any], protocol: str, port: int) -> dict[str, Any]:
    metadata: dict[str, Any] = {"service_port": port or None}
    for key in _SAFE_METADATA_FIELDS:
        value = packet.get(key)
        if value in (None, "", [], {}):
            continue
        if key == "http_path":
            metadata[key] = redact_http_path(str(value))
        elif isinstance(value, str):
            metadata[key] = redact_sensitive_text(value)
        elif isinstance(value, (list, tuple)):
            metadata[key] = [redact_sensitive_text(str(item)) for item in value]
        else:
            metadata[key] = value

    if protocol == "DNS":
        metadata["query_name"] = redact_sensitive_text(
            _text(packet.get("dns_qname"))
        )
        metadata["query_type"] = packet.get("dns_qtype")
        metadata["response_code"] = packet.get("dns_rcode")
        metadata["answer_count"] = packet.get("dns_answer_count")
    elif protocol == "HTTP":
        metadata["method"] = _text(packet.get("http_method")).upper() or None
        metadata["host"] = redact_sensitive_text(_text(packet.get("http_host")))
        metadata["path"] = redact_http_path(_text(packet.get("http_path"))) or None
        metadata["status_code"] = packet.get("http_status")
        metadata["user_agent"] = redact_sensitive_text(
            _text(packet.get("http_user_agent"))
        )
        metadata["content_type"] = redact_sensitive_text(
            _text(packet.get("http_content_type"))
        )
    elif protocol == "TLS":
        metadata["sni"] = redact_sensitive_text(
            _text(packet.get("tls_sni") or packet.get("sni"))
        )
        metadata["alpn"] = packet.get("tls_alpn") or packet.get("alpn") or []
        metadata["version"] = _text(packet.get("tls_version")) or None
        metadata["decryption"] = "not_performed"
    elif protocol in {"SSH", "RDP", "SMB", "SMTP", "IMAP", "POP3"}:
        metadata["detection"] = "signature_or_port_metadata"
        metadata["credentials_collected"] = False
    elif protocol == "UNKNOWN":
        metadata["packet_size"] = int(packet.get("length") or 0)
        metadata["transport"] = _text(packet.get("proto")).upper() or "OTHER"

    return {key: value for key, value in metadata.items() if value not in (None, "")}


def analyze_protocol(packet: dict[str, Any]) -> dict[str, Any]:
    """Return metadata-safe protocol intelligence without decryption."""

    port = _port(packet)
    transport = _text(packet.get("proto")).upper() or "OTHER"
    protocol = _normalize_protocol(packet.get("app_protocol"))
    basis = "existing packet metadata"

    if not protocol:
        if packet.get("dns_qname") or _text(packet.get("l7")).upper().startswith(
            "DNS"
        ):
            protocol, basis = "DNS", "decoded DNS metadata"
        elif packet.get("http_method") or packet.get("http_status"):
            protocol, basis = "HTTP", "decoded HTTP metadata"
        elif packet.get("tls_sni") or packet.get("tls_version") or packet.get(
            "tls_alpn"
        ):
            protocol, basis = "TLS", "visible TLS handshake metadata"
        else:
            signature = _signature_protocol(packet)
            if signature:
                protocol, basis = signature, "metadata-safe payload signature"
            elif port in _PORT_PROTOCOLS:
                protocol, basis = _PORT_PROTOCOLS[port], f"service port {port}"
            elif transport == "ICMP":
                protocol, basis = "ICMP", "network transport"
            else:
                protocol, basis = "UNKNOWN", "no recognized metadata signature"

    return {
        "app_protocol": protocol,
        "transport": transport if transport in {"TCP", "UDP", "ICMP"} else "OTHER",
        "confidence": "high"
        if basis in {"decoded DNS metadata", "decoded HTTP metadata", "visible TLS handshake metadata"}
        else "medium"
        if protocol != "UNKNOWN"
        else "low",
        "detection_basis": basis,
        "metadata": _safe_metadata(packet, protocol, port),
    }


__all__ = ["analyze_protocol"]
