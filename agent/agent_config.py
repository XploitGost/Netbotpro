from __future__ import annotations

import os
from dataclasses import dataclass


def _int_env(name: str, default: int, *, minimum: int = 1, maximum: int = 3600) -> int:
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


@dataclass(frozen=True)
class AgentConfig:
    agent_mode: bool
    agent_id: str
    display_name: str
    agent_token: str
    central_api: str
    heartbeat_interval: int
    telemetry_interval: int


def load_agent_config() -> AgentConfig:
    central_api = os.environ.get("NETBOT_CENTRAL_API", "").strip().rstrip("/")
    return AgentConfig(
        agent_mode=os.environ.get("NETBOT_AGENT_MODE", "").strip().lower()
        in {"1", "true", "yes", "on"},
        agent_id=os.environ.get("NETBOT_AGENT_ID", "").strip(),
        display_name=os.environ.get("NETBOT_AGENT_DISPLAY_NAME", "").strip(),
        agent_token=os.environ.get("NETBOT_AGENT_TOKEN", "").strip(),
        central_api=central_api,
        heartbeat_interval=_int_env("NETBOT_AGENT_HEARTBEAT_INTERVAL", 15),
        telemetry_interval=_int_env("NETBOT_AGENT_TELEMETRY_INTERVAL", 30),
    )
