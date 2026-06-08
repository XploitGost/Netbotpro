from __future__ import annotations

from collections import Counter
from typing import Any

from core.privacy_redaction import redact_sensitive_text


def analyze_tls_packets(packets: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [
        packet
        for packet in packets
        if str(packet.get("app_protocol") or "").upper() == "TLS"
        or packet.get("tls_version")
        or packet.get("tls_sni")
    ]
    versions = Counter(str(row.get("tls_version") or "unknown") for row in rows)
    sni = Counter(
        redact_sensitive_text(str(row.get("tls_sni") or row.get("sni") or ""))
        for row in rows
    )
    alpn = Counter(
        item
        for row in rows
        for item in (
            row.get("tls_alpn")
            if isinstance(row.get("tls_alpn"), list)
            else [str(row.get("tls_alpn") or row.get("alpn") or "unknown")]
        )
    )
    deprecated = sum(
        version.upper() in {"TLS 1.0", "TLS 1.1", "TLSV1", "TLSV1.1"}
        for version in versions.elements()
    )
    warnings = []
    if deprecated:
        warnings.append(
            {"type": "deprecated_tls_version", "count": deprecated, "severity": "warn"}
        )
    missing_sni = sum(
        str(row.get("direction") or "").upper() == "OUTGOING"
        and not (row.get("tls_sni") or row.get("sni"))
        for row in rows
    )
    if missing_sni:
        warnings.append(
            {"type": "missing_external_sni", "count": missing_sni, "severity": "note"}
        )
    return {
        "packet_count": len(rows),
        "tls_versions": dict(versions),
        "sni_count": sum(sni.values()),
        "top_sni": [
            {"sni": key, "count": count} for key, count in sni.most_common(10) if key
        ],
        "alpn_distribution": dict(alpn),
        "deprecated_tls_count": deprecated,
        "warnings": warnings,
        "decryption": "not_performed",
    }


__all__ = ["analyze_tls_packets"]
