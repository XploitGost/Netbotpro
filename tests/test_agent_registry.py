import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app.services.agent_registry import AgentRegistry


class AgentRegistryTests(unittest.TestCase):
    def test_register_heartbeat_and_telemetry_redact_sensitive_data(self):
        with tempfile.TemporaryDirectory() as td:
            registry = AgentRegistry(Path(td) / "agents.jsonl")

            agent = registry.register(
                {
                    "agent_id": "agent-1",
                    "hostname": "web-1",
                    "os": "Windows",
                    "capabilities": ["health"],
                },
                "agent-secret-token",
            )
            heartbeat = registry.heartbeat("agent-1", {"status": "online"})
            telemetry = registry.telemetry(
                "agent-1",
                {
                    "health": {"cpu_percent": 12},
                    "alerts_summary": {
                        "recent_alerts": [
                            {"detail": "Authorization: Bearer alert-secret"}
                        ]
                    },
                    "api_key": "raw-api-secret",
                },
            )
            stored_text = registry.storage_path.read_text(encoding="utf-8")
            public_text = json.dumps(
                {
                    "agent": registry.get_agent("agent-1"),
                    "history": registry.get_telemetry("agent-1"),
                },
                ensure_ascii=False,
            )

        self.assertEqual(agent["agent_id"], "agent-1")
        self.assertEqual(heartbeat["status"], "online")
        self.assertTrue(telemetry["ok"])
        self.assertNotIn("agent-secret-token", stored_text)
        self.assertNotIn("alert-secret", public_text)
        self.assertNotIn("raw-api-secret", public_text)
        self.assertIn("[REDACTED]", public_text)

    def test_verify_uses_configured_token_when_present(self):
        with tempfile.TemporaryDirectory() as td:
            registry = AgentRegistry(Path(td) / "agents.jsonl")
            with patch.dict(
                os.environ, {"NETBOT_AGENT_TOKEN": "central-token"}, clear=False
            ):
                registry.register({"agent_id": "agent-2"}, "central-token")

                self.assertTrue(registry.verify("agent-2", "central-token"))
                self.assertFalse(registry.verify("agent-2", "wrong-token"))


if __name__ == "__main__":
    unittest.main()
