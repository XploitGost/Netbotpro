from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.services.redaction import redact_sensitive_text

ensure_project_root_on_path()

from log_manager import LOG_DIR  # noqa: E402

AGENT_OFFLINE_AFTER_SECONDS = 90
_SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "credential",
    "authorization",
    "cookie",
    "session",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse_time(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            key_text = str(key)
            if any(marker in key_text.lower() for marker in _SENSITIVE_KEYS):
                cleaned[key_text] = "[REDACTED]"
            else:
                cleaned[key_text] = _redact(item)
        return cleaned
    if isinstance(value, list):
        return [_redact(item) for item in value[:200]]
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value


def _agent_public(record: dict[str, Any]) -> dict[str, Any]:
    item = dict(record)
    item.pop("token", None)
    item.pop("token_hash", None)
    last_seen = _parse_time(str(item.get("last_seen") or ""))
    if last_seen:
        age = (datetime.now(timezone.utc) - last_seen).total_seconds()
        item["status"] = (
            "offline"
            if age > AGENT_OFFLINE_AFTER_SECONDS
            else item.get("status", "online")
        )
    return _redact(item)


class AgentRegistry:
    def __init__(self, storage_path: str | Path | None = None) -> None:
        self.storage_path = (
            Path(storage_path) if storage_path else LOG_DIR / "agents.jsonl"
        )
        self._lock = threading.Lock()
        self._agents: dict[str, dict[str, Any]] = {}
        self._telemetry: dict[str, list[dict[str, Any]]] = {}
        self._load()

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            for line in self.storage_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                event = json.loads(line)
                event_type = event.get("type")
                agent_id = str(event.get("agent_id") or "")
                if not agent_id:
                    continue
                if event_type == "agent":
                    self._agents[agent_id] = dict(event.get("record") or {})
                elif event_type == "telemetry":
                    self._telemetry.setdefault(agent_id, []).append(
                        dict(event.get("payload") or {})
                    )
                    self._telemetry[agent_id] = self._telemetry[agent_id][-50:]
        except Exception:
            self._agents = {}
            self._telemetry = {}

    def _append(self, event: dict[str, Any]) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        with self.storage_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")

    def register(self, payload: dict[str, Any], token: str) -> dict[str, Any]:
        agent_id = str(payload.get("agent_id") or "").strip()
        if not agent_id:
            raise ValueError("agent_id is required")
        if not token:
            raise PermissionError("agent token is required")
        configured_token = os.environ.get("NETBOT_AGENT_TOKEN", "").strip()
        if configured_token and not hmac.compare_digest(configured_token, token):
            raise PermissionError("invalid agent token")
        now = _now()
        with self._lock:
            existing = self._agents.get(agent_id, {})
            record = {
                **existing,
                "agent_id": agent_id,
                "hostname": redact_sensitive_text(str(payload.get("hostname") or "")),
                "display_name": redact_sensitive_text(
                    str(
                        payload.get("display_name")
                        or payload.get("hostname")
                        or agent_id
                    )
                ),
                "os": redact_sensitive_text(str(payload.get("os") or "")),
                "platform": redact_sensitive_text(str(payload.get("platform") or "")),
                "os_version": redact_sensitive_text(
                    str(payload.get("os_version") or "")
                ),
                "machine": redact_sensitive_text(str(payload.get("machine") or "")),
                "agent_version": redact_sensitive_text(
                    str(payload.get("agent_version") or "")
                ),
                "capabilities": list(payload.get("capabilities") or []),
                "token_hash": _token_digest(token),
                "status": "online",
                "registered_at": existing.get("registered_at") or now,
                "last_seen": now,
            }
            self._agents[agent_id] = record
            self._append({"type": "agent", "agent_id": agent_id, "record": record})
            return _agent_public(record)

    def verify(self, agent_id: str, token: str) -> bool:
        agent = self._agents.get(agent_id)
        if not agent or not token:
            return False
        configured_token = os.environ.get("NETBOT_AGENT_TOKEN", "").strip()
        if configured_token:
            return hmac.compare_digest(configured_token, token)
        expected_hash = str(agent.get("token_hash") or "")
        if expected_hash:
            return hmac.compare_digest(expected_hash, _token_digest(token))
        legacy_token = str(agent.get("token") or "")
        return bool(legacy_token) and hmac.compare_digest(legacy_token, token)

    def heartbeat(self, agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if agent_id not in self._agents:
                raise KeyError(agent_id)
            record = dict(self._agents[agent_id])
            record["last_seen"] = _now()
            record["status"] = redact_sensitive_text(
                str(payload.get("status") or "online")
            )
            self._agents[agent_id] = record
            self._append({"type": "agent", "agent_id": agent_id, "record": record})
            return _agent_public(record)

    def telemetry(self, agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if agent_id not in self._agents:
                raise KeyError(agent_id)
            cleaned = _redact({**payload, "agent_id": agent_id, "received_at": _now()})
            self._telemetry.setdefault(agent_id, []).append(cleaned)
            self._telemetry[agent_id] = self._telemetry[agent_id][-50:]
            record = dict(self._agents[agent_id])
            record["last_seen"] = cleaned["received_at"]
            record["last_telemetry_at"] = cleaned["received_at"]
            record["last_telemetry"] = cleaned
            self._agents[agent_id] = record
            self._append({"type": "agent", "agent_id": agent_id, "record": record})
            self._append(
                {"type": "telemetry", "agent_id": agent_id, "payload": cleaned}
            )
            return {
                "ok": True,
                "agent_id": agent_id,
                "received_at": cleaned["received_at"],
            }

    def list_agents(self) -> list[dict[str, Any]]:
        return [
            _agent_public(record)
            for record in sorted(
                self._agents.values(),
                key=lambda item: str(item.get("display_name") or item.get("agent_id")),
            )
        ]

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        record = self._agents.get(agent_id)
        return _agent_public(record) if record else None

    def get_telemetry(self, agent_id: str, limit: int = 20) -> list[dict[str, Any]]:
        return list(self._telemetry.get(agent_id, []))[-max(1, min(50, limit)) :]
