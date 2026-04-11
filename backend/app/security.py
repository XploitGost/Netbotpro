from __future__ import annotations

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


def require_loopback(request: Request) -> None:
    client_host = request.client.host if request.client else ""
    if client_host not in {"127.0.0.1", "::1", "localhost"}:
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
    client_host = request.client.host if request.client else "unknown"
    now = time.time()
    key = (client_host, scope)
    with _RATE_LOCK:
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


def is_allowed_websocket_origin(origin: str | None) -> bool:
    if not origin:
        return True
    normalized = str(origin).strip().lower().rstrip("/")
    return normalized in {"http://127.0.0.1:5173", "http://localhost:5173"}
