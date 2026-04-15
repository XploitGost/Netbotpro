from __future__ import annotations

import ipaddress
from typing import Iterable

_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")


def clean_ip_text(value: str | None) -> str | None:
    text = str(value or "").split("%", 1)[0].strip()
    return text or None


def parse_ip(value: str | None | ipaddress._BaseAddress) -> ipaddress._BaseAddress | None:
    if isinstance(value, ipaddress._BaseAddress):
        return value
    text = clean_ip_text(value)
    if not text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def normalize_ip(value: str | None | ipaddress._BaseAddress) -> str | None:
    parsed = parse_ip(value)
    if parsed is not None:
        return str(parsed)
    return clean_ip_text(str(value) if value is not None else None)


def normalize_ip_set(values: Iterable[str | None] | None) -> set[str]:
    normalized: set[str] = set()
    for value in values or ():
        text = normalize_ip(value)
        if text:
            normalized.add(text)
    return normalized


def _normalized_local_ips(values: Iterable[str | None] | None) -> set[str]:
    if values is None:
        return set()
    if isinstance(values, set) and all(isinstance(item, str) for item in values):
        return values
    return normalize_ip_set(values)


def is_local_ip(value: str | None | ipaddress._BaseAddress, *, local_ips: Iterable[str | None] | None = None) -> bool:
    parsed = parse_ip(value)
    if parsed is None:
        return False
    normalized_local_ips = _normalized_local_ips(local_ips)
    if str(parsed) in normalized_local_ips:
        return True
    if isinstance(parsed, ipaddress.IPv4Address) and parsed in _CGNAT_V4:
        return True
    return bool(
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def is_public_ip(value: str | None | ipaddress._BaseAddress, *, local_ips: Iterable[str | None] | None = None) -> bool:
    parsed = parse_ip(value)
    if parsed is None:
        return False
    if str(parsed) in _normalized_local_ips(local_ips):
        return False
    if isinstance(parsed, ipaddress.IPv4Address) and parsed in _CGNAT_V4:
        return False
    return parsed.is_global


def is_remote_ip(value: str | None | ipaddress._BaseAddress, *, local_ips: Iterable[str | None] | None = None) -> bool:
    parsed = parse_ip(value)
    if parsed is None:
        return False
    return not is_local_ip(parsed, local_ips=local_ips)


def preferred_remote_ip(*candidates: str | None, local_ips: Iterable[str | None] | None = None) -> str | None:
    for candidate in candidates:
        normalized = normalize_ip(candidate)
        if normalized and is_remote_ip(normalized, local_ips=local_ips):
            return normalized
    for candidate in candidates:
        normalized = normalize_ip(candidate)
        if normalized:
            return normalized
    return None


def infer_flow(src: str | None, dst: str | None, *, local_ips: Iterable[str | None] | None = None) -> dict[str, str | None]:
    src_local = is_local_ip(src, local_ips=local_ips)
    dst_local = is_local_ip(dst, local_ips=local_ips)
    src_remote = is_remote_ip(src, local_ips=local_ips)
    dst_remote = is_remote_ip(dst, local_ips=local_ips)

    direction = "OTHER"
    remote_ip = preferred_remote_ip(dst, src, local_ips=local_ips)

    if src_local and dst_remote:
        direction = "OUTGOING"
        remote_ip = preferred_remote_ip(dst, src, local_ips=local_ips)
    elif src_remote and dst_local:
        direction = "INCOMING"
        remote_ip = preferred_remote_ip(src, dst, local_ips=local_ips)
    elif src_local and dst_local:
        direction = "LOCAL"
        remote_ip = normalize_ip(dst) or normalize_ip(src)

    return {
        "direction": direction,
        "remote_ip": remote_ip,
    }
