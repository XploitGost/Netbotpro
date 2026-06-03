from __future__ import annotations

from typing import Any

import requests


class AgentClient:
    def __init__(
        self, central_api: str, agent_id: str, agent_token: str, *, timeout: float = 8.0
    ) -> None:
        self.central_api = central_api.rstrip("/")
        self.agent_id = agent_id
        self.agent_token = agent_token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-NetBot-Agent-Id": self.agent_id,
            "X-NetBot-Agent-Token": self.agent_token,
        }

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = requests.post(
            f"{self.central_api}{path}",
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        if not response.content:
            return {}
        return response.json()

    def register(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.post("/agents/register", payload)

    def heartbeat(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.post("/agents/heartbeat", payload)

    def telemetry(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.post("/agents/telemetry", payload)
