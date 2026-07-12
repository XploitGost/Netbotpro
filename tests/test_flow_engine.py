from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.app.services.flow_service import FlowService
from core.flow_engine import FlowEngine, direction_for, flow_id_for, flow_key
from core.flow_risk import score_flow
from core.protocol_intelligence import analyze_protocol


def packet(**overrides):
    base = {
        "id": "pkt-1",
        "ts": "2026-06-05T12:00:00+00:00",
        "src": "10.0.0.5",
        "dst": "8.8.8.8",
        "sport": 53000,
        "dport": 443,
        "proto": "TCP",
        "direction": "OUTGOING",
        "length": 120,
    }
    return {**base, **overrides}


class ProtocolIntelligenceTests(unittest.TestCase):
    def test_dns_protocol_metadata_extraction(self):
        result = analyze_protocol(
            packet(
                proto="UDP",
                dport=53,
                dns_qname="example.org",
                dns_qtype=1,
                dns_rcode=3,
            )
        )

        self.assertEqual(result["app_protocol"], "DNS")
        self.assertEqual(result["metadata"]["query_name"], "example.org")
        self.assertEqual(result["metadata"]["response_code"], 3)

    def test_http_metadata_is_redacted(self):
        result = analyze_protocol(
            packet(
                dport=80,
                http_method="GET",
                http_host="example.org",
                http_path="/login?token=real-secret",
                http_user_agent="client password=real-secret",
                authorization="Bearer real-secret",
                cookie="session=real-secret",
            )
        )
        serialized = str(result)

        self.assertEqual(result["app_protocol"], "HTTP")
        self.assertNotIn("real-secret", serialized)
        self.assertNotIn("authorization", result["metadata"])
        self.assertNotIn("cookie", result["metadata"])

    def test_tls_metadata_without_decryption(self):
        result = analyze_protocol(
            packet(tls_sni="api.example.org", tls_version="TLS 1.3", tls_alpn=["h2"])
        )

        self.assertEqual(result["app_protocol"], "TLS")
        self.assertEqual(result["metadata"]["sni"], "api.example.org")
        self.assertEqual(result["metadata"]["decryption"], "not_performed")

    def test_unknown_protocol_fallback(self):
        result = analyze_protocol(packet(dport=65000, sport=65001, proto="UDP"))

        self.assertEqual(result["app_protocol"], "UNKNOWN")
        self.assertEqual(result["metadata"]["transport"], "UDP")


class FlowEngineTests(unittest.TestCase):
    def test_flow_key_id_and_direction(self):
        row = packet()

        self.assertEqual(flow_key(row)[0:4], ("10.0.0.5", "8.8.8.8", 53000, 443))
        self.assertTrue(flow_id_for(row).startswith("flow-"))
        self.assertEqual(direction_for(row), "outbound")
        self.assertEqual(
            direction_for(packet(src="8.8.8.8", dst="10.0.0.5", direction="")),
            "inbound",
        )

    def test_flow_aggregation_counts_duration_bytes_and_timeline(self):
        engine = FlowEngine()
        first = engine.ingest(packet(tls_sni="api.example.org"))
        second = engine.ingest(
            packet(
                id="pkt-2",
                ts="2026-06-05T12:00:02+00:00",
                length=300,
                tls_sni="api.example.org",
            ),
            [{"id": "alert-1", "severity": "high", "attack_type": "Synthetic alert"}],
        )

        self.assertEqual(first["packets_count"], 1)
        self.assertEqual(second["packets_count"], 2)
        self.assertEqual(second["bytes_total"], 420)
        self.assertEqual(second["duration_ms"], 2000)
        self.assertIn("alert-1", second["related_alert_ids"])
        self.assertIn(
            "flow_started", [item["event_type"] for item in second["timeline"]]
        )
        self.assertIn(
            "tls_handshake_metadata",
            [item["event_type"] for item in second["timeline"]],
        )
        self.assertIn(
            "alert_triggered", [item["event_type"] for item in second["timeline"]]
        )

    def test_flow_samples_and_metadata_never_keep_raw_secret(self):
        flow = FlowEngine().ingest(
            packet(
                dport=80,
                http_method="GET",
                http_path="/?token=real-secret",
                summary="Authorization: Bearer real-secret",
                payload_ascii="password=real-secret",
            )
        )

        self.assertNotIn("real-secret", str(flow))
        self.assertNotIn("payload_ascii", str(flow))

    def test_risk_score_levels(self):
        low = score_flow({"direction": "internal", "app_protocol": "DNS"})
        medium = score_flow(
            {
                "direction": "outbound",
                "app_protocol": "UNKNOWN",
                "new_destination": True,
            }
        )
        high = score_flow(
            {
                "direction": "outbound",
                "app_protocol": "TLS",
                "new_destination": True,
                "metadata": {"sni": "new.example"},
                "alert_counts": {"high": 2},
            }
        )
        critical = score_flow(
            {
                "direction": "outbound",
                "app_protocol": "UNKNOWN",
                "new_destination": True,
                "alert_counts": {"critical": 2},
            }
        )

        self.assertEqual(low["level"], "low")
        self.assertEqual(medium["level"], "medium")
        self.assertEqual(high["level"], "high")
        self.assertEqual(critical["level"], "critical")

    def test_sqlite_schema_and_retention(self):
        with tempfile.TemporaryDirectory() as td:
            service = FlowService(db_path=Path(td) / "flows.db")
            flow = service.ingest(packet())

            self.assertEqual(service.get_flow(flow["flow_id"])["packets_count"], 1)
            self.assertTrue((Path(td) / "flows.db").is_file())
            self.assertGreaterEqual(service.cleanup_history(7), 0)

    def test_flow_snapshots_are_coalesced_and_written_in_batches(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "flows.db"
            service = FlowService(db_path=db_path, batch_persistence=True)
            try:
                service.ingest(packet())
                service.ingest(packet(id="pkt-2", ts="2026-06-05T12:00:01+00:00"))
            finally:
                service.close()

            conn = sqlite3.connect(db_path)
            try:
                rows = conn.execute("SELECT snapshot_json FROM flows").fetchall()
            finally:
                conn.close()

            self.assertEqual(len(rows), 1)
            self.assertEqual(json.loads(rows[0][0])["packets_count"], 2)
            stats = service.persistence_stats()
            self.assertEqual(stats["accepted_total"], 2)
            self.assertEqual(stats["persisted_total"], 1)
            self.assertEqual(stats["flush_batches"], 1)


if __name__ == "__main__":
    unittest.main()
