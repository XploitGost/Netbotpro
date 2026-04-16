from __future__ import annotations

import threading
from typing import Any

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.security import normalize_ip_csv, sanitize_iface_name

ensure_project_root_on_path()

from config.settings_manager import load_settings, save_settings  # noqa: E402
from log_manager import init_storage, set_persist  # noqa: E402


BOOL_KEYS = {
    "autostart_sniffer",
    "auto_block",
    "ids_signature_enabled",
    "ids_ml_enabled",
    "right_log_enabled",
    "group_alerts",
    "safe_mode",
    "persist_logs",
    "mask_ip_logs",
}

FLOAT_KEYS = {
    "ids_ml_threshold": (0.0, 1.0),
    "ids_ml_contamination": (0.0, 1.0),
    "tr_timeout": (0.2, 10.0),
}

INT_KEYS = {
    "sniffer_sample_rate": (1, 10),
    "retention_minutes": (0, 60 * 24 * 365),
    "tr_max_hops": (1, 64),
    "tr_queries": (1, 5),
    "tr_port": (1, 65535),
}

STR_ENUM_KEYS = {
    "language": {"fa", "en"},
    "theme": {"dark", "light"},
    "tr_mode": {"UDP", "TCP", "ICMP"},
}

_LOCK = threading.Lock()
_SETTINGS_CACHE: dict[str, Any] = load_settings()


def _apply_runtime_settings(settings: dict[str, Any]) -> None:
    persist_enabled = bool(settings.get("persist_logs"))
    set_persist(persist_enabled)
    if persist_enabled:
        init_storage()


def _cached_copy() -> dict[str, Any]:
    with _LOCK:
        return dict(_SETTINGS_CACHE)


def _replace_cache(settings: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(settings)
    with _LOCK:
        _SETTINGS_CACHE.clear()
        _SETTINGS_CACHE.update(normalized)
        return dict(_SETTINGS_CACHE)


_apply_runtime_settings(_SETTINGS_CACHE)


def get_settings() -> dict[str, Any]:
    return _cached_copy()


def get_settings_snapshot() -> dict[str, Any]:
    return _cached_copy()


def reload_settings() -> dict[str, Any]:
    current = _replace_cache(load_settings())
    _apply_runtime_settings(current)
    return current


def update_settings(data: dict[str, Any]) -> dict[str, Any]:
    current = get_settings_snapshot()
    for key, value in data.items():
        if key in BOOL_KEYS:
            current[key] = bool(value)
        elif key in FLOAT_KEYS:
            low, high = FLOAT_KEYS[key]
            try:
                current[key] = max(low, min(high, float(value)))
            except (TypeError, ValueError):
                continue
        elif key in INT_KEYS:
            low, high = INT_KEYS[key]
            try:
                current[key] = max(low, min(high, int(value)))
            except (TypeError, ValueError):
                continue
        elif key in STR_ENUM_KEYS:
            normalized = str(value).upper() if key == "tr_mode" else str(value).lower()
            allowed = STR_ENUM_KEYS[key]
            if normalized in allowed:
                current[key] = normalized
        elif key == "iface":
            current[key] = sanitize_iface_name(str(value))
        elif key == "whitelist_ips":
            current[key] = normalize_ip_csv(str(value))
    save_settings(current)
    current = _replace_cache(current)
    _apply_runtime_settings(current)
    return current
