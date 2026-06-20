from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.security import require_local_token, require_trusted_client
from backend.app.services.monitoring_service import build_monitoring_metrics


class MonitoringMetricsTests(unittest.TestCase):
    def test_build_monitoring_metrics_reports_healthy_snapshot(self):
        payload = build_monitoring_metrics(
            sniffer_state={
                "running": True,
                "iface": "Ethernet",
                "total_packets": 12,
                "total_alerts": 1,
            },
            observability={
                "event_bus": {"subscribers": 1, "published_messages": 20},
                "packet_queue": {
                    "max_size": 2000,
                    "queue_size": 0,
                    "queue_high_water_mark": 4,
                    "accepted_packets": 12,
                    "dropped_packets": 0,
                    "overflow_policy": "drop_oldest",
                },
                "persistence": {
                    "queue_size": 0,
                    "queue_high_water_mark": 4,
                    "persisted_packets": 12,
                    "persisted_alerts": 1,
                    "avg_flush_ms": 3.5,
                    "overload_policy": "drop_oldest",
                },
                "history": {
                    "packets_list": {
                        "calls": 2,
                        "errors": 0,
                        "slow_calls": 0,
                        "max_ms": 8.0,
                    }
                },
                "auto_block": {"blocked": 0},
            },
            flow_summary={
                "total_flows": 3,
                "active_flows": 3,
                "external_flows": 2,
                "internal_flows": 1,
                "risk_distribution": {"low": 3},
            },
        )

        self.assertEqual(payload["health"], "healthy")
        self.assertEqual(payload["capture"]["total_packets"], 12)
        self.assertEqual(payload["packet_queue"]["accepted_packets"], 12)
        self.assertEqual(payload["flows"]["total_flows"], 3)
        self.assertEqual(payload["pressure_reasons"], [])

    def test_build_monitoring_metrics_reports_pressure(self):
        payload = build_monitoring_metrics(
            sniffer_state={"running": True, "packet_count": 5, "alert_count": 0},
            observability={
                "event_bus": {"dropped_messages": 2},
                "packet_queue": {
                    "max_size": 100,
                    "queue_size": 90,
                    "queue_high_water_mark": 95,
                    "accepted_packets": 250,
                    "dropped_packets": 120,
                    "dropped_oldest": 120,
                    "overflow_policy": "drop_oldest",
                },
                "persistence": {
                    "queue_size": 4200,
                    "queue_high_water_mark": 5000,
                    "dropped_writes": 150,
                    "flush_errors": 4,
                },
                "history": {
                    "packets_list": {
                        "errors": 1,
                        "slow_calls": 2,
                        "max_ms": 300,
                    }
                },
                "auto_block": {},
            },
            flow_summary={},
        )

        self.assertEqual(payload["health"], "critical")
        self.assertIn("packet_queue_backlog", payload["pressure_reasons"])
        self.assertIn("packet_queue_high_water", payload["pressure_reasons"])
        self.assertIn("packet_queue_dropped_packets", payload["pressure_reasons"])
        self.assertIn("persistence_queue_backlog", payload["pressure_reasons"])
        self.assertIn("websocket_dropped_messages", payload["pressure_reasons"])
        self.assertIn("history_query_latency", payload["pressure_reasons"])


class MonitoringMetricsApiTests(unittest.TestCase):
    def setUp(self):
        app.dependency_overrides[require_trusted_client] = lambda: None
        app.dependency_overrides[require_local_token] = lambda: None
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()

    def test_monitoring_metrics_endpoint_returns_compact_snapshot(self):
        with (
            patch(
                "backend.app.main.sniffer_service.get_state",
                return_value={"running": False, "iface": "default"},
            ),
            patch("backend.app.main._observability_snapshot", return_value={}),
            patch("backend.app.main.flow_service.summary", return_value={}),
        ):
            response = self.client.get("/api/monitoring/metrics")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("generated_at", payload)
        self.assertIn("capture", payload)
        self.assertIn("persistence", payload)
        self.assertEqual(payload["health"], "healthy")


if __name__ == "__main__":
    unittest.main()
