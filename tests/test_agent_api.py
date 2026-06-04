import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app import main
from backend.app.services.agent_registry import AgentRegistry


class AgentApiTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.registry = AgentRegistry(Path(self.tempdir.name) / "agents.db")
        self.original_registry = main.agent_registry
        main.agent_registry = self.registry
        self.client = TestClient(main.app)

    def tearDown(self):
        main.agent_registry = self.original_registry
        self.tempdir.cleanup()

    def _headers(self, token="agent-token"):
        return {
            "X-NetBot-Agent-Id": "agent-api-1",
            "X-NetBot-Agent-Token": token,
        }

    def test_register_heartbeat_and_telemetry_flow(self):
        with patch.dict(os.environ, {"NETBOT_AGENT_TOKEN": "agent-token"}, clear=False):
            registered = self.client.post(
                "/api/agents/register",
                headers=self._headers(),
                json={"hostname": "api-host"},
            )
            heartbeat = self.client.post(
                "/api/agents/heartbeat",
                headers=self._headers(),
                json={"status": "online"},
            )
            telemetry = self.client.post(
                "/api/agents/telemetry",
                headers=self._headers(),
                json={
                    "health": {"cpu_percent": 20},
                    "alerts_summary": {
                        "total_alerts": 2,
                        "critical_count": 1,
                    },
                    "flows_summary": {"flow_count": 4},
                },
            )
            with patch.dict(
                os.environ,
                {
                    "NETBOT_AGENT_TOKEN": "agent-token",
                    "NETBOT_REMOTE_ACCESS": "1",
                    "NETBOT_LOCAL_TOKEN": "local-token",
                },
                clear=False,
            ):
                agents = self.client.get(
                    "/api/agents",
                    headers={"X-NetBot-Token": "local-token"},
                )
                overview = self.client.get(
                    "/api/agents/overview",
                    headers={"X-NetBot-Token": "local-token"},
                )
                health = self.client.get(
                    "/api/agents/agent-api-1/health/history?range=24h",
                    headers={"X-NetBot-Token": "local-token"},
                )
                alerts = self.client.get(
                    "/api/agents/agent-api-1/alerts/history?range=24h",
                    headers={"X-NetBot-Token": "local-token"},
                )
                risk = self.client.get(
                    "/api/agents/agent-api-1/risk/history?range=24h",
                    headers={"X-NetBot-Token": "local-token"},
                )
                alerts_summary = self.client.get(
                    "/api/agents/alerts/summary",
                    headers={"X-NetBot-Token": "local-token"},
                )
                risk_summary = self.client.get(
                    "/api/agents/risk/summary",
                    headers={"X-NetBot-Token": "local-token"},
                )

        self.assertEqual(registered.status_code, 200)
        self.assertEqual(registered.json()["agent"]["agent_id"], "agent-api-1")
        self.assertEqual(heartbeat.status_code, 200)
        self.assertEqual(telemetry.status_code, 200)
        self.assertEqual(agents.status_code, 200)
        self.assertEqual(agents.json()[0]["agent_id"], "agent-api-1")
        self.assertEqual(overview.status_code, 200)
        self.assertEqual(overview.json()["total_agents"], 1)
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["items"][0]["cpu_percent"], 20)
        self.assertEqual(alerts.status_code, 200)
        self.assertEqual(alerts.json()["items"][0]["critical_count"], 1)
        self.assertEqual(risk.status_code, 200)
        self.assertIn("score", risk.json()["items"][0])
        self.assertEqual(alerts_summary.status_code, 200)
        self.assertEqual(alerts_summary.json()["critical_count"], 1)
        self.assertEqual(risk_summary.status_code, 200)
        self.assertIn("buckets", risk_summary.json())

    def test_heartbeat_rejects_missing_or_wrong_token(self):
        with patch.dict(os.environ, {"NETBOT_AGENT_TOKEN": "agent-token"}, clear=False):
            self.client.post(
                "/api/agents/register",
                headers=self._headers(),
                json={"hostname": "api-host"},
            )
            missing = self.client.post(
                "/api/agents/heartbeat",
                headers={"X-NetBot-Agent-Id": "agent-api-1"},
                json={"status": "online"},
            )
            wrong = self.client.post(
                "/api/agents/heartbeat",
                headers=self._headers("wrong-token"),
                json={"status": "online"},
            )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 401)


if __name__ == "__main__":
    unittest.main()
