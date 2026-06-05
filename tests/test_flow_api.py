from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.security import require_local_token, require_trusted_client
from backend.app.services.flow_service import FlowService


class FlowApiTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.service = FlowService(db_path=Path(self.tempdir.name) / "flows.db")
        self.service.ingest(
            {
                "id": "pkt-api-1",
                "ts": "2026-06-05T12:00:00+00:00",
                "src": "10.0.0.5",
                "dst": "8.8.8.8",
                "sport": 50000,
                "dport": 80,
                "proto": "TCP",
                "direction": "OUTGOING",
                "length": 250,
                "http_method": "GET",
                "http_host": "example.org",
                "http_path": "/login?token=real-secret",
                "summary": "Cookie: session=real-secret",
            },
            [{"id": "alert-api-1", "severity": "high", "attack_type": "Test alert"}],
        )
        self.client = TestClient(app)
        app.dependency_overrides[require_trusted_client] = lambda: None
        app.dependency_overrides[require_local_token] = lambda: None

    def tearDown(self):
        app.dependency_overrides.clear()
        self.tempdir.cleanup()

    def test_flow_protocol_timeline_and_report_endpoints_are_redacted(self):
        with patch("backend.app.main.flow_service", self.service):
            flows = self.client.get("/api/flows")
            summary = self.client.get("/api/flows/summary")
            protocols = self.client.get("/api/protocols/summary")
            report = self.client.get("/api/reports/flows/summary")
            report_csv = self.client.get("/api/reports/flows/summary.csv")
            flow_id = flows.json()["items"][0]["flow_id"]
            timeline = self.client.get(f"/api/flows/{flow_id}/timeline")

        for response in [flows, summary, protocols, report, report_csv, timeline]:
            self.assertEqual(response.status_code, 200)
            self.assertNotIn("real-secret", response.text)
            self.assertNotIn("Cookie: session=real-secret", response.text)
        self.assertEqual(flows.json()["items"][0]["app_protocol"], "HTTP")
        self.assertTrue(timeline.json()["items"])
        self.assertIn("flow_id,app_protocol", report_csv.text)
        self.assertEqual(report_csv.headers["content-type"], "text/csv; charset=utf-8")

    def test_flow_since_filter(self):
        with patch("backend.app.main.flow_service", self.service):
            included = self.client.get(
                "/api/flows", params={"since": "2026-06-05T11:59:00+00:00"}
            )
            excluded = self.client.get(
                "/api/flows", params={"since": "2026-06-05T12:01:00+00:00"}
            )

        self.assertEqual(included.json()["total"], 1)
        self.assertEqual(excluded.json()["total"], 0)

    def test_conversation_and_protocol_flow_endpoints(self):
        with patch("backend.app.main.flow_service", self.service):
            conversations = self.client.get("/api/conversations")
            protocol_flows = self.client.get("/api/protocols/HTTP/flows")
            conversation_id = conversations.json()[0]["conversation_id"]
            detail = self.client.get(f"/api/conversations/{conversation_id}")

        self.assertEqual(conversations.status_code, 200)
        self.assertEqual(protocol_flows.json()["total"], 1)
        self.assertEqual(detail.json()["conversation_id"], conversation_id)


if __name__ == "__main__":
    unittest.main()
