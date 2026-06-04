import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app.services.agent_registry import AgentRegistry, compute_agent_risk


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

    def test_sqlite_schema_auto_init_and_history_tables(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "agents.db"
            registry = AgentRegistry(db_path)

            registry.register({"agent_id": "agent-sql", "hostname": "sql-host"}, "tok")
            registry.heartbeat("agent-sql", {"status": "online"})
            registry.telemetry(
                "agent-sql",
                {
                    "health": {
                        "cpu_percent": 91,
                        "memory_percent": 82,
                        "disk_percent": 70,
                    },
                    "capture": {
                        "capture_running": True,
                        "capture_mode": "metadata",
                    },
                    "alerts_summary": {
                        "total_alerts": 3,
                        "critical_count": 1,
                        "high_count": 1,
                    },
                    "flows_summary": {"flow_count": 12},
                },
            )

            health = registry.history("agent-sql", "health")
            alerts = registry.history("agent-sql", "alerts")
            risk = registry.history("agent-sql", "risk")
            telemetry = registry.get_telemetry("agent-sql")
            db_exists = db_path.exists()

        self.assertTrue(db_exists)
        self.assertEqual(len(health), 1)
        self.assertEqual(health[0]["cpu_percent"], 91)
        self.assertEqual(alerts[0]["critical_count"], 1)
        self.assertGreaterEqual(risk[0]["score"], 60)
        self.assertEqual(len(telemetry), 1)

    def test_sqlite_redacts_before_storing_history(self):
        with tempfile.TemporaryDirectory() as td:
            registry = AgentRegistry(Path(td) / "agents.db")
            registry.register({"agent_id": "agent-redact"}, "tok")

            registry.telemetry(
                "agent-redact",
                {
                    "alerts_summary": {
                        "recent_alerts": [
                            {"detail": "Authorization: Bearer store-secret"}
                        ]
                    },
                    "flows_summary": {
                        "top_sources": ["https://example.test/?api_key=flow-secret"]
                    },
                },
            )
            public_text = json.dumps(
                {
                    "agent": registry.get_agent("agent-redact"),
                    "telemetry": registry.get_telemetry("agent-redact"),
                    "alerts": registry.history("agent-redact", "alerts"),
                    "flows": registry.history("agent-redact", "flows"),
                },
                ensure_ascii=False,
            )

        self.assertNotIn("store-secret", public_text)
        self.assertNotIn("flow-secret", public_text)
        self.assertIn("[REDACTED]", public_text)

    def test_offline_detection_uses_env_threshold(self):
        with tempfile.TemporaryDirectory() as td:
            registry = AgentRegistry(Path(td) / "agents.db")
            registry.register({"agent_id": "agent-old"}, "tok")
            registry._agents["agent-old"]["last_seen"] = "2000-01-01T00:00:00+00:00"
            registry._upsert_agent(registry._agents["agent-old"])

            with patch.dict(
                os.environ,
                {"NETBOT_AGENT_OFFLINE_AFTER_SECONDS": "5"},
                clear=False,
            ):
                agent = registry.get_agent("agent-old")

        self.assertEqual(agent["status"], "offline")

    def test_risk_score_labels(self):
        self.assertEqual(compute_agent_risk(alerts={"low_count": 1})["severity"], "low")
        self.assertEqual(
            compute_agent_risk(alerts={"medium_count": 3})["severity"],
            "medium",
        )
        self.assertEqual(
            compute_agent_risk(alerts={"high_count": 3})["severity"],
            "high",
        )
        self.assertEqual(
            compute_agent_risk(alerts={"critical_count": 3})["severity"],
            "critical",
        )


if __name__ == "__main__":
    unittest.main()
