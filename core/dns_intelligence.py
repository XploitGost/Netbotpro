from __future__ import annotations

import math
from collections import Counter
from typing import Any

from core.privacy_redaction import redact_sensitive_text


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in counts.values()
    )


def analyze_dns_packets(packets: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [
        packet
        for packet in packets
        if str(packet.get("app_protocol") or "").upper() == "DNS"
        or packet.get("dns_qname")
        or packet.get("dns_query")
    ]
    domains = [
        redact_sensitive_text(str(row.get("dns_qname") or row.get("dns_query") or ""))
        for row in rows
    ]
    rcodes = Counter(str(row.get("dns_rcode") or "NOERROR").upper() for row in rows)
    qtypes = Counter(
        str(row.get("dns_qtype") or row.get("dns_query_type") or "UNKNOWN").upper()
        for row in rows
    )
    domain_counts = Counter(domain for domain in domains if domain)
    nxdomain = rcodes["NXDOMAIN"] + rcodes["3"]
    suspicious = []
    for domain, count in domain_counts.items():
        longest_label = max(domain.split("."), key=len, default="")
        reasons = []
        if len(domain) > 80:
            reasons.append("very_long_domain")
        if len(longest_label) >= 16 and _entropy(longest_label) >= 3.6:
            reasons.append("high_entropy_label")
        if count >= 5:
            reasons.append("repeated_query")
        if reasons:
            suspicious.append({"domain": domain, "count": count, "reasons": reasons})
    rate = (nxdomain / len(rows)) if rows else 0.0
    if rate >= 0.35 and rows:
        suspicious.insert(
            0, {"domain": "*", "count": nxdomain, "reasons": ["high_nxdomain_rate"]}
        )
    return {
        "query_count": len(rows),
        "unique_domains": len(domain_counts),
        "query_type_distribution": dict(qtypes),
        "rcode_distribution": dict(rcodes),
        "nxdomain_count": nxdomain,
        "nxdomain_rate": round(rate, 4),
        "top_domains": [
            {"domain": key, "count": count}
            for key, count in domain_counts.most_common(10)
        ],
        "suspicious": suspicious[:25],
    }


__all__ = ["analyze_dns_packets"]
