from __future__ import annotations

import logging
import time
from pathlib import Path

from agent.agent_client import AgentClient
from agent.agent_config import load_agent_config
from agent.agent_identity import (
    build_registration_payload,
    default_identity_path,
    load_or_create_agent_id,
)
from agent.agent_payloads import build_telemetry_payload
from core.privacy_redaction import redact_sensitive_text

logger = logging.getLogger("netbotpro.agent")


def sanitize_agent_log_message(message: object, *secrets: str) -> str:
    """Remove known agent secrets before writing operational logs."""
    text = redact_sensitive_text(str(message))
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def run_agent() -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    config = load_agent_config()
    if not config.central_api:
        logger.error("agent central api is not configured")
        return 2
    if not config.agent_token:
        logger.error("agent token is not configured")
        return 2
    identity_path = default_identity_path(Path.cwd())
    agent_id = load_or_create_agent_id(identity_path, config.agent_id)
    client = AgentClient(config.central_api, agent_id, config.agent_token)
    registration = build_registration_payload(agent_id, config.display_name)
    backoff = 2
    next_heartbeat = 0.0
    next_telemetry = 0.0
    registered = False
    logger.info(
        "starting NetBotPro agent id=%s central=%s", agent_id, config.central_api
    )
    try:
        while True:
            now = time.monotonic()
            try:
                if not registered:
                    client.register(registration)
                    registered = True
                    backoff = 2
                    logger.info("agent registered id=%s", agent_id)
                if now >= next_heartbeat:
                    client.heartbeat({"agent_id": agent_id, "status": "online"})
                    next_heartbeat = now + config.heartbeat_interval
                if now >= next_telemetry:
                    client.telemetry(build_telemetry_payload(agent_id))
                    next_telemetry = now + config.telemetry_interval
                time.sleep(1)
            except Exception as exc:
                registered = False
                logger.warning(
                    "agent sync failed; retrying in %ss: %s",
                    backoff,
                    sanitize_agent_log_message(exc, config.agent_token),
                )
                time.sleep(backoff)
                backoff = min(60, backoff * 2)
    except KeyboardInterrupt:
        logger.info("agent shutdown requested")
        return 0


if __name__ == "__main__":
    raise SystemExit(run_agent())
