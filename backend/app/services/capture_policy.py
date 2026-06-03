from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request

from backend.app.security import is_remote_access_enabled
from backend.app.services.settings_service import get_settings_snapshot


CAPTURE_MODES = {"metadata", "full", "forensic"}


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _normalized_mode(value: Any) -> str:
    mode = str(value or "").strip().lower()
    return mode if mode in CAPTURE_MODES else "metadata"


@dataclass(frozen=True)
class CapturePolicy:
    mode: str
    allow_full_capture: bool
    payload_capture_enabled: bool
    redact_sensitive_data: bool
    safe_use_accepted: bool
    retention_days: int
    forensic_duration_minutes: int
    forensic_confirmed: bool
    remote_access_enabled: bool

    @property
    def is_full_like(self) -> bool:
        return self.mode in {"full", "forensic"}

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "capture_mode": self.mode,
            "allow_full_capture": self.allow_full_capture,
            "payload_capture_enabled": self.payload_capture_enabled,
            "redact_sensitive_data": self.redact_sensitive_data,
            "safe_use_accepted": self.safe_use_accepted,
            "retention_days": self.retention_days,
            "forensic_duration_minutes": self.forensic_duration_minutes,
            "forensic_confirmed": self.forensic_confirmed,
            "remote_access_enabled": self.remote_access_enabled,
        }


def current_capture_policy(payload: dict[str, Any] | None = None) -> CapturePolicy:
    payload = payload or {}
    settings = get_settings_snapshot()
    mode = _normalized_mode(
        payload.get("capture_mode")
        or os.environ.get("NETBOT_CAPTURE_MODE")
        or settings.get("capture_mode")
        or "metadata"
    )
    allow_full = _truthy(os.environ.get("NETBOT_ALLOW_FULL_CAPTURE")) or bool(settings.get("allow_full_capture"))
    safe_use = _truthy(os.environ.get("NETBOT_SAFE_USE_ACCEPTED")) or bool(settings.get("safe_use_policy_accepted"))
    payload_capture = _truthy(os.environ.get("NETBOT_PAYLOAD_CAPTURE")) or bool(settings.get("payload_capture_enabled"))
    redact_sensitive = not str(os.environ.get("NETBOT_REDACT_SENSITIVE_DATA", "1")).strip().lower() in {"0", "false", "no", "off"}
    retention_days = _int_env("NETBOT_RETENTION_DAYS", 7)
    duration = int(payload.get("forensic_duration_minutes") or settings.get("forensic_duration_minutes") or 0)
    forensic_confirmed = bool(payload.get("forensic_confirmed") or settings.get("forensic_confirmed"))
    if mode == "metadata":
        payload_capture = False
    if mode == "forensic" and duration <= 0 and forensic_confirmed:
        duration = 0
    return CapturePolicy(
        mode=mode,
        allow_full_capture=allow_full,
        payload_capture_enabled=payload_capture,
        redact_sensitive_data=redact_sensitive,
        safe_use_accepted=safe_use,
        retention_days=max(1, min(3650, retention_days)),
        forensic_duration_minutes=max(0, min(24 * 60, duration)),
        forensic_confirmed=forensic_confirmed,
        remote_access_enabled=is_remote_access_enabled(),
    )


def enforce_capture_policy(payload: dict[str, Any] | None, request: Request | None = None) -> CapturePolicy:
    policy = current_capture_policy(payload)
    if policy.mode == "metadata":
        return policy
    if not policy.safe_use_accepted:
        raise HTTPException(status_code=451, detail="Safe Use Policy must be accepted before full or forensic capture")
    if not policy.allow_full_capture:
        raise HTTPException(status_code=403, detail="Full capture requires NETBOT_ALLOW_FULL_CAPTURE=1")
    if policy.mode == "forensic" and policy.forensic_duration_minutes <= 0 and not policy.forensic_confirmed:
        raise HTTPException(status_code=400, detail="Forensic capture requires a duration or explicit stop confirmation")
    return policy
