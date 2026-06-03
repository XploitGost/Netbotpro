from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any

from backend.app.bootstrap import ensure_project_root_on_path

ensure_project_root_on_path()

from log_manager import LOG_DIR  # noqa: E402


_AUDIT_LOCK = threading.Lock()
_AUDIT_PATH = LOG_DIR / "audit.jsonl"
_SENSITIVE_KEYS = {"token", "authorization", "cookie", "password", "secret", "x-netbot-token"}


def _clean_detail(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in _SENSITIVE_KEYS or any(marker in key_text.lower() for marker in _SENSITIVE_KEYS):
                cleaned[key_text] = "[REDACTED]"
            else:
                cleaned[key_text] = _clean_detail(item)
        return cleaned
    if isinstance(value, list):
        return [_clean_detail(item) for item in value[:50]]
    if isinstance(value, tuple):
        return [_clean_detail(item) for item in value[:50]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def audit_event(action: str, *, actor: str = "unknown", success: bool = True, detail: dict[str, Any] | None = None) -> None:
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": str(action or "unknown"),
        "actor": str(actor or "unknown"),
        "success": bool(success),
        "detail": _clean_detail(detail or {}),
    }
    try:
        _AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event, ensure_ascii=False, sort_keys=True)
        with _AUDIT_LOCK:
            with _AUDIT_PATH.open("a", encoding="utf-8") as handle:
                handle.write(f"{line}\n")
    except Exception:
        # Audit must never break capture or response handling.
        return


def audit_path() -> str:
    return str(_AUDIT_PATH)
