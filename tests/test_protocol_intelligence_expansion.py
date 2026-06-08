from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.security import require_local_token, require_trusted_client
from backend.app.services.saved_filter_service import SavedFilterService
from core.display_filter import filter_suggestions
from core.dns_intelligence import analyze_dns_packets
from core.http_intelligence import analyze_http_packets
from core.tcp_analysis import analyze_tcp_packets
from core.tls_intelligence import analyze_tls_packets


class ProtocolIntelligenceExpansionTests(unittest.TestCase):
    def test_display_filter_suggestions_are_safe_and_complete(self):
        suggestions = filter_suggestions()
        for field in (
            "ip.addr",
            "tcp.flags.reset",
            "dns.rcode",
            "http.status",
            "tls.sni",
        ):
            self.assertIn(field, suggestions["fields"])

    def test_saved_filter_crud_and_builtins(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            service = SavedFilterService(Path(temp_dir) / "filters.json")
            self.assertTrue(any(item["is_builtin"] for item in service.list()))
            row = service.create({"name": "TLS", "expression": "protocol == TLS"})
            updated = service.update(row["id"], {"description": "TLS metadata"})
            self.assertEqual(updated["description"], "TLS metadata")
            service.delete(row["id"])
            self.assertFalse(any(item["id"] == row["id"] for item in service.list()))

    def test_tcp_dns_http_tls_summaries(self):
        packets = [
            {"id": "1", "proto": "TCP", "flags": "S"},
            {"id": "2", "proto": "TCP", "flags": "SA"},
            {"id": "3", "proto": "TCP", "flags": "A"},
            {
                "id": "4",
                "app_protocol": "DNS",
                "dns_qname": "a.example",
                "dns_rcode": "NXDOMAIN",
            },
            {
                "id": "5",
                "app_protocol": "HTTP",
                "direction": "OUTGOING",
                "http_method": "GET",
                "http_host": "example.org",
                "http_path": "/login?token=raw-secret",
                "authorization": "Bearer raw-secret",
            },
            {
                "id": "6",
                "app_protocol": "TLS",
                "tls_sni": "example.org",
                "tls_version": "TLS 1.0",
            },
        ]
        self.assertTrue(analyze_tcp_packets(packets)["handshake_complete"])
        self.assertEqual(analyze_dns_packets(packets)["nxdomain_count"], 1)
        http = analyze_http_packets(packets)
        self.assertEqual(http["external_cleartext_http_count"], 1)
        self.assertNotIn("raw-secret", str(http))
        tls = analyze_tls_packets(packets)
        self.assertEqual(tls["deprecated_tls_count"], 1)
        self.assertEqual(tls["decryption"], "not_performed")


class ProtocolIntelligenceApiTests(unittest.TestCase):
    def setUp(self):
        app.dependency_overrides[require_trusted_client] = lambda: None
        app.dependency_overrides[require_local_token] = lambda: None
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()

    def test_suggestions_and_protocol_intelligence_endpoints(self):
        safe = {
            "protocols": {"protocols": []},
            "tcp": {},
            "dns": {},
            "http": {"authorization": "[REDACTED]"},
            "tls": {"decryption": "not_performed"},
        }
        with patch(
            "backend.app.main.packet_detail_service.protocol_intelligence",
            return_value=safe,
        ):
            suggestions = self.client.get("/api/packets/filter/suggestions")
            intelligence = self.client.get("/api/protocols/intelligence")
            report = self.client.get("/api/reports/inspection/summary")
        self.assertEqual(suggestions.status_code, 200)
        self.assertEqual(intelligence.status_code, 200)
        self.assertEqual(report.status_code, 200)
        self.assertNotIn("raw-secret", intelligence.text + report.text)

    def test_saved_filter_api_crud(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            service = SavedFilterService(Path(temp_dir) / "filters.json")
            with patch("backend.app.main.saved_filter_service", service):
                created = self.client.post(
                    "/api/filters",
                    json={"name": "HTTP errors", "expression": "http.status >= 400"},
                )
                filter_id = created.json()["id"]
                listed = self.client.get("/api/filters")
                updated = self.client.patch(
                    f"/api/filters/{filter_id}",
                    json={"description": "Review HTTP failures"},
                )
                deleted = self.client.delete(f"/api/filters/{filter_id}")
        self.assertEqual(created.status_code, 200)
        self.assertTrue(any(item["id"] == filter_id for item in listed.json()))
        self.assertEqual(updated.json()["description"], "Review HTTP failures")
        self.assertEqual(deleted.json(), {"ok": True})

    def test_packet_search_endpoint_returns_redacted_output(self):
        result = {
            "query": "http",
            "total": 1,
            "items": [{"summary": "token=[REDACTED]"}],
        }
        with patch(
            "backend.app.main.packet_detail_service.search", return_value=result
        ):
            response = self.client.get("/api/packets/search", params={"q": "http"})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("raw-secret", response.text)


if __name__ == "__main__":
    unittest.main()
