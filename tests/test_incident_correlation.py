from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.main import app, sniffer_service
from backend.app.security import require_local_token, require_trusted_client
from backend.app.services.incident_correlation import (
    IncidentCorrelationEngine,
    incident_markdown_summary,
)


def signal(index: int = 1, **overrides):
    value = {
        "incident_type": "possible_beaconing",
        "timestamp": (
            datetime.now(timezone.utc) + timedelta(seconds=index)
        ).isoformat(),
        "source_host": "10.0.0.5",
        "destination_host": "203.0.113.20",
        "application": "browser.exe",
        "service": "Unknown encrypted destination",
        "domain": "unknown.example",
        "flow_key": "flow-1",
        "source": "alert" if index % 2 else "flow",
        "summary": f"Repeated encrypted signal {index}",
        "severity": "medium",
        "risk_reasons": ["Unknown encrypted service"],
    }
    value.update(overrides)
    return value


class IncidentCorrelationTests(unittest.TestCase):
    def test_single_weak_signal_does_not_create_incident(self):
        engine = IncidentCorrelationEngine()
        self.assertIsNone(engine.ingest_signal(signal()))
        self.assertEqual(engine.list_incidents()["count"], 0)

    def test_related_signals_create_and_update_incident(self):
        engine = IncidentCorrelationEngine(
            high_signal_threshold=3, critical_signal_threshold=5
        )
        engine.ingest_signal(signal(1))
        created = engine.ingest_signal(signal(2))
        updated = engine.ingest_signal(signal(3))

        self.assertIsNotNone(created)
        self.assertEqual(created["incident_id"], updated["incident_id"])
        self.assertEqual(updated["signal_count"], 3)
        self.assertEqual(updated["severity"], "high")
        self.assertEqual(updated["confidence"], "high")
        self.assertTrue(updated["correlation_reasons"])
        self.assertTrue(updated["recommended_investigation_steps"])
        self.assertTrue(updated["false_positive_notes"])

    def test_unrelated_sources_are_separated(self):
        engine = IncidentCorrelationEngine()
        engine.ingest_signal(signal(1))
        engine.ingest_signal(signal(2))
        engine.ingest_signal(signal(3, source_host="10.0.0.8", flow_key="flow-2"))
        engine.ingest_signal(signal(4, source_host="10.0.0.8", flow_key="flow-2"))
        self.assertEqual(engine.list_incidents()["count"], 2)

    def test_timeline_is_sorted_bounded_and_redacted(self):
        engine = IncidentCorrelationEngine(max_signals_per_incident=3)
        engine.ingest_signal(signal(2, summary="Authorization: Bearer raw-secret"))
        incident = engine.ingest_signal(signal(1))
        for index in range(3, 7):
            incident = engine.ingest_signal(signal(index))
        rendered = str(incident)
        timestamps = [row["timestamp"] for row in incident["timeline"]]
        self.assertNotIn("raw-secret", rendered)
        self.assertLessEqual(len(timestamps), 3)
        self.assertEqual(timestamps, sorted(timestamps))

    def test_max_open_and_retention_are_bounded(self):
        engine = IncidentCorrelationEngine(max_open=1, retention_hours=24)
        engine.ingest_signal(signal(1))
        engine.ingest_signal(signal(2))
        engine.ingest_signal(
            signal(
                3,
                incident_type="suspicious_dns",
                source_host="10.0.0.8",
                flow_key="flow-2",
            )
        )
        engine.ingest_signal(
            signal(
                4,
                incident_type="suspicious_dns",
                source_host="10.0.0.8",
                flow_key="flow-2",
            )
        )
        self.assertEqual(engine.list_incidents(status="all")["count"], 1)
        self.assertGreater(engine.metrics()["signals_dropped_total"], 0)

    def test_malformed_signal_is_ignored_and_metrics_are_recorded(self):
        engine = IncidentCorrelationEngine()
        self.assertIsNone(engine.ingest_signal({"password": "secret"}))
        metrics = engine.metrics()
        self.assertEqual(metrics["signals_received_total"], 1)
        self.assertEqual(metrics["signals_ignored_total"], 1)
        self.assertNotIn("secret", str(metrics))

    def test_markdown_summary_contains_context_and_redacts_sensitive_values(self):
        summary_start = datetime.now(timezone.utc)
        markdown = incident_markdown_summary(
            {
                "title": "Possible Beaconing",
                "severity": "high",
                "confidence": "medium",
                "status": "open",
                "first_seen": summary_start.isoformat(),
                "last_seen": (summary_start + timedelta(minutes=5)).isoformat(),
                "source_hosts": ["10.0.0.5"],
                "applications": ["browser.exe"],
                "services": ["Unknown encrypted destination"],
                "domains": ["unknown.example"],
                "evidence": ["Authorization: Bearer markdown-secret"],
                "correlation_reasons": ["Repeated encrypted destination"],
                "recommended_investigation_steps": ["Review the destination."],
                "false_positive_notes": ["Background update traffic."],
                "timeline": [
                    {
                        "timestamp": (summary_start + timedelta(minutes=1)).isoformat(),
                        "severity": "high",
                        "summary": "Cookie: session=timeline-secret",
                        "source": "alert",
                    }
                ],
            }
        )
        self.assertIn("# Possible Beaconing", markdown)
        self.assertIn("**Severity:** high", markdown)
        self.assertIn("## Evidence", markdown)
        self.assertIn("## Timeline", markdown)
        self.assertIn("## Correlation Reasons", markdown)
        self.assertNotIn("markdown-secret", markdown)
        self.assertNotIn("timeline-secret", markdown)
        self.assertIn("[REDACTED]", markdown)


class IncidentApiTests(unittest.TestCase):
    def setUp(self):
        app.dependency_overrides[require_trusted_client] = lambda: None
        app.dependency_overrides[require_local_token] = lambda: None
        self.client = TestClient(app)
        self.engine = IncidentCorrelationEngine()
        self.engine.ingest_signal(signal(1))
        self.incident = self.engine.ingest_signal(
            signal(2, summary="Cookie: token=api-secret")
        )

    def tearDown(self):
        app.dependency_overrides.clear()

    def test_list_detail_and_monitoring_are_redacted(self):
        with patch.object(sniffer_service, "_incident_correlation", self.engine):
            listing = self.client.get("/api/incidents")
            detail = self.client.get(f"/api/incidents/{self.incident['incident_id']}")
            monitoring = self.client.get("/api/monitoring/metrics")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(listing.json()["count"], 1)
        self.assertEqual(
            listing.json()["items"][0]["incident_id"], self.incident["incident_id"]
        )
        self.assertEqual(
            detail.json()["incident"]["incident_id"], self.incident["incident_id"]
        )
        self.assertIn("incidents", monitoring.json())
        self.assertNotIn("api-secret", listing.text + detail.text + monitoring.text)

    def test_summary_endpoint_returns_redacted_markdown(self):
        with patch.object(sniffer_service, "_incident_correlation", self.engine):
            response = self.client.get(
                f"/api/incidents/{self.incident['incident_id']}/summary"
            )
        self.assertEqual(response.status_code, 200)
        markdown = response.json()["markdown"]
        self.assertIn("# Possible Beaconing", markdown)
        self.assertIn("## Evidence", markdown)
        self.assertIn("## Timeline", markdown)
        self.assertNotIn("api-secret", markdown)


if __name__ == "__main__":
    unittest.main()
