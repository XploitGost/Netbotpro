import gc
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from backend.app.services.agent_demo import seed_demo_data
from backend.app.services.agent_registry import (
    AgentRegistry,
    compute_agent_risk,
    normalize_capabilities,
)


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

    def test_node_metadata_is_redacted_and_capabilities_are_safe(self):
        with tempfile.TemporaryDirectory() as td:
            registry = AgentRegistry(Path(td) / "agents.jsonl")

            agent = registry.register(
                {
                    "agent_id": "sensor-1",
                    "node_name": "Branch sensor token=private-value",
                    "node_type": "sensor",
                    "profile": "sensor",
                    "version": "0.2.0",
                    "platform": "linux",
                    "capabilities": [
                        "telemetry",
                        "redacted_flow_metadata",
                    ],
                },
                "tok",
            )

        self.assertEqual(agent["node_id"], "sensor-1")
        self.assertEqual(agent["node_type"], "sensor")
        self.assertTrue(agent["metadata_redacted"])
        self.assertNotIn("private-value", json.dumps(agent))

    def test_forbidden_capabilities_are_rejected(self):
        with self.assertRaises(ValueError):
            normalize_capabilities(["telemetry", "remote_shell"])

        with tempfile.TemporaryDirectory() as td:
            registry = AgentRegistry(Path(td) / "agents.jsonl")
            with self.assertRaises(ValueError):
                registry.register(
                    {
                        "agent_id": "unsafe-agent",
                        "capabilities": ["command_execution"],
                    },
                    "tok",
                )

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

    def test_seed_demo_data_creates_agents_and_redacted_history(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "agents.db"
            result = seed_demo_data(db_path, count=4, reset=True)
            registry = AgentRegistry(db_path)
            agents = registry.list_agents()
            public_text = json.dumps(
                {
                    "agents": agents,
                    "overview": registry.overview(),
                    "summary": registry.fleet_summary_report(),
                },
                ensure_ascii=False,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["created_agents"], 4)
        self.assertEqual(len(agents), 4)
        self.assertIn("demo_data", public_text)
        self.assertNotIn("netbotpro-demo-token", public_text)
        self.assertNotIn("Authorization", public_text)

    def test_history_ranges_include_1h_24h_7d_30d(self):
        with tempfile.TemporaryDirectory() as td:
            registry = AgentRegistry(Path(td) / "agents.db")
            registry.register({"agent_id": "range-agent"}, "tok")
            registry.telemetry("range-agent", {"health": {"cpu_percent": 33}})

            counts = {
                name: len(registry.history("range-agent", "health", name))
                for name in ["1h", "24h", "7d", "30d"]
            }

        self.assertEqual(counts, {"1h": 1, "24h": 1, "7d": 1, "30d": 1})

    def test_cleanup_history_removes_old_rows_but_keeps_agents(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "agents.db"
            registry = AgentRegistry(db_path)
            registry.register({"agent_id": "cleanup-agent"}, "tok")
            registry.telemetry("cleanup-agent", {"health": {"cpu_percent": 20}})
            old_time = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    "UPDATE agent_health_snapshots SET received_at = ? WHERE agent_id = ?",
                    (old_time, "cleanup-agent"),
                )
                conn.commit()
            finally:
                conn.close()

            dry_run = registry.cleanup_history(30, dry_run=True)
            result = registry.cleanup_history(30)
            agent = registry.get_agent("cleanup-agent")
            health = registry.history("cleanup-agent", "health", "30d")
            del registry
            gc.collect()

        self.assertEqual(dry_run["deleted"]["agent_health_snapshots"], 1)
        self.assertEqual(result["deleted"]["agent_health_snapshots"], 1)
        self.assertIsNotNone(agent)
        self.assertEqual(health, [])


if __name__ == "__main__":
    unittest.main()
