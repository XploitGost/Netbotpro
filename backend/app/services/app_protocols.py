from __future__ import annotations

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
    123: ("NTP", "infra"),
    135: ("MSRPC", "infra"),
    139: ("SMB", "file-share"),
    143: ("IMAP", "email"),
    389: ("LDAP", "directory"),
    443: ("HTTPS", "web"),
    445: ("SMB", "file-share"),
    465: ("SMTPS", "email"),
    587: ("SMTP", "email"),
    636: ("LDAPS", "directory"),
    993: ("IMAPS", "email"),
    995: ("POP3S", "email"),
    1433: ("MSSQL", "database"),
    1521: ("ORACLE", "database"),
    3306: ("MYSQL", "database"),
    3389: ("RDP", "remote-access"),
    5432: ("POSTGRES", "database"),
    5900: ("VNC", "remote-access"),
    6379: ("REDIS", "database"),
    8080: ("HTTP", "web"),
    8443: ("HTTPS", "web"),
    9200: ("ELASTIC", "infra"),
    9443: ("HTTPS", "web"),
}


def _normalize_alpn(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def _port_candidates(packet: dict[str, Any]) -> list[int]:
    ports: list[int] = []
    for field in ("dport", "sport"):
        try:
            value = int(packet.get(field) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            ports.append(value)
    return ports


def infer_app_protocol(packet: dict[str, Any]) -> dict[str, Any]:
    l7 = str(packet.get("l7") or "").strip()
    l7_upper = l7.upper()
    proto = str(packet.get("proto") or "").upper()
    tls_sni = str(packet.get("tls_sni") or packet.get("sni") or "").strip()
    tls_alpn = _normalize_alpn(packet.get("tls_alpn") or packet.get("alpn"))
    http_method = str(packet.get("http_method") or "").strip().upper()
    http_host = str(packet.get("http_host") or "").strip()
    dns_qname = str(packet.get("dns_qname") or "").strip()
    ports = _port_candidates(packet)

    app_protocol = ""
    app_category = "unknown"
    app_confidence = "low"

    if dns_qname or l7_upper.startswith("DNS "):
        app_protocol = "DNS"
        app_category = "dns"
        app_confidence = "high"
    elif http_method or http_host or l7_upper.startswith("HTTP "):
        app_protocol = "HTTP"
        app_category = "web"
        app_confidence = "high"
    elif proto == "UDP" and 443 in ports and any(item.lower().startswith("h3") for item in tls_alpn):
        app_protocol = "QUIC"
        app_category = "web"
        app_confidence = "high"
    elif tls_sni or tls_alpn or l7_upper == "TLS":
        if any(port in {443, 8443, 9443} for port in ports):
            app_protocol = "HTTPS"
            app_category = "web"
            app_confidence = "high" if tls_sni or tls_alpn else "medium"
        else:
            app_protocol = "TLS"
            app_category = "encrypted"
            app_confidence = "medium"
    else:
        for port in ports:
            mapped = _PORT_PROTOCOLS.get(port)
            if mapped:
                app_protocol, app_category = mapped
                app_confidence = "medium"
                break

    if not app_protocol:
        app_protocol = proto or "OTHER"

    return {
        "app_protocol": app_protocol,
        "app_category": app_category,
        "app_confidence": app_confidence,
    }

