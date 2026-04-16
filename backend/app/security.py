from __future__ import annotations

import base64
import hmac
import os
import ipaddress
import re
import threading
import time
from pathlib import Path

from fastapi import HTTPException, Request


_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_RATE_LIMITS: dict[tuple[str, str], list[float]] = {}
_RATE_LOCK = threading.Lock()
_DEFAULT_ALLOWED_ORIGINS = ("http://127.0.0.1:5173", "http://localhost:5173")
_MAX_RATE_LIMIT_KEYS = 4096
_SAFE_DOWNLOAD_SUFFIXES = {".csv", ".xlsx", ".pdf", ".html", ".zip"}
WEBSOCKET_APP_PROTOCOL = "netbot.v1"
_WEBSOCKET_AUTH_PREFIX = "netbot.auth."


def _strip_brackets(value: str) -> str:
    text = str(value or "").strip()
    if text.startswith("[") and text.endswith("]"):
        return text[1:-1]
    return text


def _is_loopback_host(value: str) -> bool:
    text = _strip_brackets(value).strip().lower()
    if not text:
        return False
    if text == "localhost":
        return True
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped.is_loopback
    return parsed.is_loopback


def is_loopback_host(value: str) -> bool:
    return _is_loopback_host(value)


def _normalize_origin(origin: str) -> str:
    text = str(origin or "").strip().lower()
    if text in {"file://", "file:", "null"}:
        return "null" if text == "null" else "file://"
    return text.rstrip("/")


def allowed_origins() -> list[str]:
    raw = os.environ.get("NETBOT_ALLOWED_ORIGINS", "").strip()
    items = [item.strip() for item in raw.split(",") if item.strip()] if raw else list(_DEFAULT_ALLOWED_ORIGINS)
    normalized: list[str] = []
    for item in items:
        value = _normalize_origin(item)
        if value and value not in normalized:
            normalized.append(value)
    return normalized


def require_loopback(request: Request) -> None:
    client_host = request.client.host if request.client else ""
    if not _is_loopback_host(client_host):
        raise HTTPException(status_code=403, detail="Local access only")


def is_local_token_enabled() -> bool:
    return bool(os.environ.get("NETBOT_LOCAL_TOKEN", "").strip())


def _expected_local_token() -> str:
    return os.environ.get("NETBOT_LOCAL_TOKEN", "").strip()


def check_local_token(provided: str) -> bool:
    expected = _expected_local_token()
    if not expected:
        return True
    actual = (provided or "").strip()
    return hmac.compare_digest(actual, expected)


def require_local_token(request: Request) -> None:
    provided = request.headers.get("X-NetBot-Token", "").strip()
    if not check_local_token(provided):
        raise HTTPException(status_code=401, detail="Invalid local token")


def enforce_rate_limit(request: Request, scope: str, limit: int, window_sec: int) -> None:
    client_host = request.client.host if request and request.client else "unknown"
    now = time.time()
    key = (client_host, scope)
    with _RATE_LOCK:
        if len(_RATE_LIMITS) > _MAX_RATE_LIMIT_KEYS:
            cutoff = now - max(1, window_sec)
            stale_keys = [item for item, history in _RATE_LIMITS.items() if not history or max(history) < cutoff]
            for stale_key in stale_keys[: len(_RATE_LIMITS) - _MAX_RATE_LIMIT_KEYS]:
                _RATE_LIMITS.pop(stale_key, None)
        history = _RATE_LIMITS.get(key, [])
        history = [ts for ts in history if now - ts < window_sec]
        if len(history) >= limit:
            raise HTTPException(status_code=429, detail=f"Rate limit exceeded for {scope}")
        history.append(now)
        _RATE_LIMITS[key] = history


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid IP address") from exc


def validate_block_ip(value: str) -> str:
    try:
        parsed = ipaddress.ip_address((value or "").strip())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid IP address") from exc
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast:
        raise HTTPException(status_code=400, detail="Unsupported firewall target")
    return str(parsed)


def validate_traceroute_target(value: str) -> str:
    target = (value or "").strip()
    if not target or len(target) > 253:
        raise HTTPException(status_code=400, detail="Invalid traceroute target")
    if any(ch.isspace() for ch in target) or "/" in target or "\\" in target:
        raise HTTPException(status_code=400, detail="Invalid traceroute target")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        if _HOST_RE.fullmatch(target) is None or ".." in target or target.startswith(".") or target.endswith("."):
            raise HTTPException(status_code=400, detail="Invalid traceroute target")
        return target


def validate_export_name(value: str, suffix: str) -> str:
    raw = (value or "").strip() or "netbot_export"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._-") or "netbot_export"
    safe = safe[:96].rstrip("._-") or "netbot_export"
    if not safe.endswith(suffix):
        safe = f"{safe}{suffix}"
    return safe


def ensure_within_directory(base_dir: str, candidate: str) -> str:
    base = Path(base_dir).resolve()
    target = (base / candidate).resolve()
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Unsafe export path")
    return str(target)


def validate_report_download_path(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        raise HTTPException(status_code=400, detail="Missing export path")
    name = Path(candidate).name
    if name != candidate:
        raise HTTPException(status_code=400, detail="Unsafe export path")
    if Path(name).suffix.lower() not in _SAFE_DOWNLOAD_SUFFIXES:
        raise HTTPException(status_code=400, detail="Unsupported export file type")
    return name


def normalize_ip_csv(value: str, *, max_items: int = 128) -> str:
    items: list[str] = []
    seen: set[str] = set()
    for raw in str(value or "").split(","):
        text = raw.strip()
        if not text:
            continue
        try:
            normalized = str(ipaddress.ip_address(text))
        except ValueError:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        items.append(normalized)
        if len(items) >= max_items:
            break
    return ", ".join(items)


def sanitize_iface_name(value: str, *, maximum_length: int = 512) -> str:
    text = str(value or "").strip()
    if not text:
        return "iface=default"
    text = "".join(ch for ch in text if ch.isprintable() and ch not in "\r\n\t")
    text = text[:maximum_length].strip()
    return text or "iface=default"


def extract_websocket_token(protocol_header: str | None, query_token: str | None) -> tuple[str, str | None]:
    accepted_protocol = None
    token = ""
    for raw_item in str(protocol_header or "").split(","):
        item = raw_item.strip()
        if not item:
            continue
        if item == WEBSOCKET_APP_PROTOCOL:
            accepted_protocol = WEBSOCKET_APP_PROTOCOL
            continue
        if item.startswith(_WEBSOCKET_AUTH_PREFIX):
            encoded = item[len(_WEBSOCKET_AUTH_PREFIX):].strip()
            if not encoded:
                continue
            padding = "=" * ((4 - len(encoded) % 4) % 4)
            try:
                decoded = base64.urlsafe_b64decode(f"{encoded}{padding}".encode("ascii")).decode("utf-8")
            except Exception as exc:
                raise HTTPException(status_code=400, detail="Invalid websocket auth token") from exc
            token = decoded.strip()
    if token:
        return token, accepted_protocol
    return str(query_token or "").strip(), accepted_protocol


def is_allowed_websocket_origin(origin: str | None) -> bool:
    if not origin:
        return True
    return _normalize_origin(str(origin)) in set(allowed_origins())
