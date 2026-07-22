from __future__ import annotations

import ipaddress
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

SUPPORTED_PROFILES = {"dev", "desktop", "server", "sensor", "agent"}
NODE_TYPES = {"server", "sensor", "agent"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_INSECURE_SECRETS = {
    "changeme",
    "change-me",
    "default",
    "secret",
    "password",
    "netbotpro",
    "netbotpro-secret",
    "dev-token",
}
APP_STARTED_AT = time.time()


@dataclass(frozen=True)
class RuntimeProfileConfig:
    profile: str
    host: str
    port: int
    public_base_url: str
    allowed_origins: tuple[str, ...]
    trusted_tokens: tuple[str, ...]
    runtime_dir: Path
    log_dir: Path
    enable_live_capture: bool
    debug: bool
    server_mode: bool
    validation_errors: tuple[str, ...] = field(default_factory=tuple)
    validation_warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def public_bind(self) -> bool:
        return is_public_bind(self.host)


def _bool(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _split_csv(value: str | None) -> tuple[str, ...]:
    items: list[str] = []
    for raw in str(value or "").split(","):
        item = raw.strip()
        if item and item not in items:
            items.append(item)
    return tuple(items)


def normalize_profile(value: str | None, *, default: str = "desktop") -> str:
    profile = str(value or default).strip().lower()
    if profile not in SUPPORTED_PROFILES:
        raise ValueError(f"Unsupported NETBOT_PROFILE '{profile}'")
    return profile


def is_loopback_bind(host: str) -> bool:
    text = str(host or "").strip().strip("[]").lower()
    if text in LOCAL_HOSTS:
        return True
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped.is_loopback
    return parsed.is_loopback


def is_public_bind(host: str) -> bool:
    text = str(host or "").strip().strip("[]").lower()
    if not text:
        return False
    if text in {"0.0.0.0", "::"}:
        return True
    return not is_loopback_bind(text)


def _path_writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".netbotpro_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def load_runtime_profile_config(
    env: Mapping[str, str] | None = None,
    *,
    validate_paths: bool = True,
) -> RuntimeProfileConfig:
    source = env if env is not None else os.environ
    profile = normalize_profile(source.get("NETBOT_PROFILE"))
    host = str(source.get("NETBOT_HOST") or "127.0.0.1").strip()
    try:
        port = int(source.get("NETBOT_PORT") or "8000")
    except (TypeError, ValueError):
        port = 8000
    allowed_origins = _split_csv(source.get("NETBOT_ALLOWED_ORIGINS"))
    local_token = str(source.get("NETBOT_LOCAL_TOKEN") or "").strip()
    trusted_tokens = _split_csv(source.get("NETBOT_TRUSTED_TOKENS"))
    if local_token and local_token not in trusted_tokens:
        trusted_tokens = (local_token, *trusted_tokens)
    runtime_dir = Path(source.get("NETBOT_RUNTIME_DIR") or source.get("NETBOT_DATA_DIR") or ".runtime")
    log_dir = Path(source.get("NETBOT_LOG_DIR") or runtime_dir / "logs")
    debug = _bool(source.get("NETBOT_DEBUG") or source.get("DEBUG"))
    server_mode = profile == "server" or _bool(source.get("NETBOT_SERVER_MODE"))

    errors: list[str] = []
    warnings: list[str] = []
    if server_mode:
        if not trusted_tokens:
            errors.append("server_profile_requires_trusted_token")
        if any(token.lower() in DEFAULT_INSECURE_SECRETS for token in trusted_tokens):
            errors.append("server_profile_rejects_default_secret")
        if "*" in allowed_origins:
            errors.append("server_profile_rejects_wildcard_cors")
        if debug:
            errors.append("server_profile_rejects_debug")
        if is_public_bind(host) and not allowed_origins:
            errors.append("server_profile_requires_explicit_origins_for_public_bind")
        if is_public_bind(host) and not str(source.get("NETBOT_PUBLIC_BASE_URL") or "").strip():
            warnings.append("server_profile_public_base_url_recommended")
        if validate_paths:
            if not _path_writable(runtime_dir):
                errors.append("runtime_dir_not_writable")
            if not _path_writable(log_dir):
                errors.append("log_dir_not_writable")

    return RuntimeProfileConfig(
        profile=profile,
        host=host,
        port=port,
        public_base_url=str(source.get("NETBOT_PUBLIC_BASE_URL") or "").strip(),
        allowed_origins=allowed_origins,
        trusted_tokens=trusted_tokens,
        runtime_dir=runtime_dir,
        log_dir=log_dir,
        enable_live_capture=_bool(source.get("NETBOT_ENABLE_LIVE_CAPTURE")),
        debug=debug,
        server_mode=server_mode,
        validation_errors=tuple(errors),
        validation_warnings=tuple(warnings),
    )


def require_valid_runtime_config(config: RuntimeProfileConfig) -> None:
    if config.validation_errors:
        joined = ", ".join(config.validation_errors)
        raise RuntimeError(f"Unsafe NetBotPro runtime configuration: {joined}")


def profile_metadata(config: RuntimeProfileConfig | None = None) -> dict[str, object]:
    active = config or load_runtime_profile_config(validate_paths=False)
    return {
        "profile": active.profile,
        "server_mode": active.server_mode,
        "host": active.host,
        "port": active.port,
        "public_base_url_configured": bool(active.public_base_url),
        "allowed_origins_count": len(active.allowed_origins),
        "trusted_tokens_configured": bool(active.trusted_tokens),
        "runtime_dir": str(active.runtime_dir),
        "log_dir": str(active.log_dir),
        "live_capture_enabled": active.enable_live_capture,
        "validation": {
            "ok": not active.validation_errors,
            "errors": list(active.validation_errors),
            "warnings": list(active.validation_warnings),
        },
    }

