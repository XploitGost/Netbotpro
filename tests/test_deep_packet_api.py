from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.security import require_local_token, require_trusted_client


class DeepPacketApiTests(unittest.TestCase):
    def setUp(self):
        app.dependency_overrides[require_trusted_client] = lambda: None
        app.dependency_overrides[require_local_token] = lambda: None
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()

    def test_filter_help_and_invalid_packet_filter(self):
        help_response = self.client.get("/api/packets/filter/help")
        invalid = self.client.get("/api/packets", params={"filter": "ip.src =="})
        self.assertEqual(help_response.status_code, 200)
        self.assertIn("examples", help_response.json())
        self.assertEqual(invalid.status_code, 400)

    def test_packet_detail_hex_and_expert_endpoints_are_redacted(self):
        details = {
            "packet_id": "pkt-1",
            "layers": [],
            "hex": {"rows": [], "warning": "redacted"},
            "expert_items": [],
        }
        packet = {"id": "pkt-1", "summary": "token=[REDACTED]"}
        with (
            patch("backend.app.main.packet_detail_service.details", AsyncMock(return_value=details)),
            patch("backend.app.main.packet_detail_service.hex_view", AsyncMock(return_value=details["hex"])),
            patch("backend.app.main.packet_detail_service.packet", AsyncMock(return_value=packet)),
        ):
            detail_response = self.client.get("/api/packets/pkt-1/details")
            hex_response = self.client.get("/api/packets/pkt-1/hex")
            expert_response = self.client.get("/api/packets/pkt-1/expert")
        for response in (detail_response, hex_response, expert_response):
            self.assertEqual(response.status_code, 200)
            self.assertNotIn("raw-secret", response.text)

    def test_packet_and_expert_reports_are_available(self):
        report = {"total_packets": 0, "top_protocols": [], "expert_warnings": {}}
        expert = {"total": 0, "items": [], "severity": {}}
        with (
            patch("backend.app.main.packet_detail_service.packet_report", return_value=report),
            patch("backend.app.main.packet_detail_service.expert_summary", return_value=expert),
        ):
            self.assertEqual(self.client.get("/api/reports/packet-analysis/summary").status_code, 200)
            self.assertEqual(self.client.get("/api/expert/summary").status_code, 200)


if __name__ == "__main__":
    unittest.main()
