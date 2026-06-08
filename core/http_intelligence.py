from __future__ import annotations

from collections import Counter
from typing import Any

from core.privacy_redaction import (
    redact_http_path,
    redact_sensitive_data,
    redact_sensitive_text,
)


def analyze_http_packets(packets: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [
        packet
        for packet in packets
        if str(packet.get("app_protocol") or "").upper() == "HTTP"
        or packet.get("http_method")
        or packet.get("http_status")
    ]
    methods = Counter(str(row.get("http_method") or "UNKNOWN").upper() for row in rows)
    statuses = Counter(str(row.get("http_status") or "unknown") for row in rows)
    groups = Counter(
        f"{int(row.get('http_status')) // 100}xx"
        for row in rows
        if str(row.get("http_status") or "").isdigit()
    )
    hosts = Counter(
        redact_sensitive_text(str(row.get("http_host") or "")) for row in rows
    )
    content_types = Counter(
        redact_sensitive_text(
            str(row.get("http_content_type") or row.get("content_type") or "unknown")
        )
        for row in rows
    )
    suspicious = []
    keywords = {"admin", "login", "upload", "shell", "cmd", "wp-admin"}
    for row in rows:
        path = redact_http_path(str(row.get("http_path") or "")) or ""
        reasons = []
        status = int(row.get("http_status") or 0)
        if status >= 400:
            reasons.append("http_error")
        if str(row.get("direction") or "").upper() == "OUTGOING":
            reasons.append("external_cleartext_http")
        if any(keyword in path.lower() for keyword in keywords):
            reasons.append("sensitive_path_keyword")
        if not row.get("http_host"):
            reasons.append("missing_host")
        if reasons:
            suspicious.append(
                redact_sensitive_data(
                    {
                        "packet_id": row.get("id"),
                        "method": row.get("http_method"),
                        "host": row.get("http_host"),
                        "path": path,
                        "status": status or None,
                        "reasons": reasons,
                    }
                )
            )
    return redact_sensitive_data(
        {
            "request_count": len(rows),
            "method_distribution": dict(methods),
            "status_code_distribution": dict(statuses),
            "status_group_distribution": dict(groups),
            "top_hosts": [
                {"host": key, "count": count}
                for key, count in hosts.most_common(10)
                if key
            ],
            "top_content_types": [
                {"content_type": key, "count": count}
                for key, count in content_types.most_common(10)
            ],
            "cleartext_http_count": len(rows),
            "external_cleartext_http_count": sum(
                str(row.get("direction") or "").upper() == "OUTGOING" for row in rows
            ),
            "suspicious": suspicious[:25],
        }
    )


__all__ = ["analyze_http_packets"]
