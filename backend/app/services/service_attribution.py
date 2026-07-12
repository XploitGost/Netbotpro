from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

from core.privacy_redaction import redact_sensitive_data, redact_sensitive_text

SERVICE_PATTERNS = (
    (
        "YouTube",
        "Video Streaming",
        (
            "youtube.com",
            "*.youtube.com",
            "googlevideo.com",
            "*.googlevideo.com",
            "youtu.be",
        ),
    ),
    (
        "Google",
        "Search / Cloud",
        (
            "google.com",
            "*.google.com",
            "gstatic.com",
            "*.gstatic.com",
            "1e100.net",
            "*.1e100.net",
        ),
    ),
    (
        "GitHub",
        "Developer",
        (
            "github.com",
            "*.github.com",
            "githubusercontent.com",
            "*.githubusercontent.com",
        ),
    ),
    ("Telegram", "Messaging", ("telegram.org", "*.telegram.org", "t.me", "*.t.me")),
    ("Cloudflare", "CDN / Security", ("cloudflare.com", "*.cloudflare.com")),
)

ORG_FALLBACKS = (
    ("google", "Google Services", "Search / Cloud"),
    ("cloudflare", "Cloudflare Network", "CDN / Security"),
    ("github", "GitHub", "Developer"),
    ("microsoft", "Microsoft Services", "Cloud"),
    ("amazon", "Amazon / AWS", "Cloud / CDN"),
)


def _domain(packet: dict[str, Any]) -> tuple[str, str]:
    candidates = (
        ("tls_sni", packet.get("tls_sni") or packet.get("sni")),
        ("http_host", packet.get("http_host")),
        ("dns", packet.get("dns_qname")),
    )
    for source, value in candidates:
        normalized = str(value or "").strip().lower().rstrip(".")
        if normalized:
            return normalized, source
    return "", ""


def attribute_service(packet: dict[str, Any]) -> dict[str, Any]:
    domain, source = _domain(packet)
    application = str(packet.get("process_name") or "").strip()
    org = str(packet.get("org") or "").strip()
    encrypted = int(packet.get("sport") or packet.get("dport") or 0) == 443 or str(
        packet.get("app_protocol") or ""
    ).upper() in {"TLS", "HTTPS", "QUIC"}

    for service, category, patterns in SERVICE_PATTERNS:
        if domain and any(fnmatch(domain, pattern) for pattern in patterns):
            return redact_sensitive_data(
                {
                    "application_name": application,
                    "service_name": service,
                    "service_category": category,
                    "service_domain": domain,
                    "service_confidence": "high",
                    "service_reasons": [f"{source.upper()} matched {domain}"],
                    "service_sources": [source],
                    "service_encrypted": encrypted,
                    "service_unknown": False,
                }
            )

    org_lower = org.lower()
    for org_pattern, service, category in ORG_FALLBACKS:
        if org_pattern in org_lower:
            return redact_sensitive_data(
                {
                    "application_name": application,
                    "service_name": service,
                    "service_category": category,
                    "service_domain": domain,
                    "service_confidence": "low",
                    "service_reasons": [
                        f"Network organization matched {redact_sensitive_text(org)}",
                        "Encrypted traffic did not expose a reliable service domain",
                    ],
                    "service_sources": ["asn_org"],
                    "service_encrypted": encrypted,
                    "service_unknown": False,
                }
            )

    return {
        "application_name": application,
        "service_name": "Unknown Encrypted" if encrypted else "Unknown",
        "service_category": "Unknown",
        "service_domain": domain,
        "service_confidence": "unknown",
        "service_reasons": ["No reliable DNS, SNI, HTTP Host, or organization match"],
        "service_sources": [],
        "service_encrypted": encrypted,
        "service_unknown": True,
    }


def enrich_service_attribution(packet: dict[str, Any]) -> dict[str, Any]:
    attribution = attribute_service(packet)
    packet.update(attribution)
    return attribution


__all__ = ["attribute_service", "enrich_service_attribution"]
