from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch
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
    def test_multirow_chunks_are_atomic_and_preserve_all_rows(self):
        with tempfile.TemporaryDirectory() as folder:
            service = FlowService(db_path=Path(folder)/'flows.db', persistent_writer=True)
            try:
                base = service.engine.ingest(packet())
                rows = [dict(base, flow_id=f'flow-{i}') for i in range(205)]
                service._write_snapshots(rows)
                with closing(sqlite3.connect(service.db_path)) as reader:
                    self.assertEqual(reader.execute('SELECT COUNT(*) FROM flows').fetchone()[0], 205)
                broken = [dict(row, risk_score=77) for row in rows]
                broken[-1]['app_protocol'] = None
                with self.assertRaises(sqlite3.IntegrityError):
                    service._write_snapshots(broken)
                with closing(sqlite3.connect(service.db_path)) as reader:
                    self.assertEqual(reader.execute('SELECT COUNT(*) FROM flows WHERE risk_score=77').fetchone()[0], 0)
            finally:
                service.close()

    def test_identical_snapshot_does_not_rewrite_but_changed_evidence_does(self):
        with tempfile.TemporaryDirectory() as folder:
            service = FlowService(db_path=Path(folder)/'flows.db', persistent_writer=True)
            try:
                flow = service.ingest(packet())
                before = service._snapshot_connection.total_changes
                service._write_snapshots([flow])
                self.assertEqual(service._snapshot_connection.total_changes, before)
                changed = dict(flow, packets_count=2)
                service._write_snapshots([changed])
                self.assertEqual(service._snapshot_connection.total_changes, before + 1)
                with closing(sqlite3.connect(service.db_path)) as reader:
                    saved = json.loads(reader.execute('SELECT snapshot_json FROM flows').fetchone()[0])
                self.assertEqual(saved['packets_count'], 2)
            finally:
                service.close()

    def test_storage_serializes_outside_connection_lock_and_reports_stages(self):
        with tempfile.TemporaryDirectory() as folder:
            service = FlowService(db_path=Path(folder)/'flows.db', persistent_writer=True)
            states = []
            original = json.dumps
            def serialize(*args, **kwargs):
                states.append(service._snapshot_lock._is_owned())
                return original(*args, **kwargs)
            try:
                with patch('backend.app.services.flow_service.json.dumps', side_effect=serialize):
                    service.ingest(packet())
                self.assertEqual(states, [False])
                metrics = service.storage_metrics()
                self.assertEqual(metrics['batches'], 1)
                self.assertEqual(metrics['last_batch_flows'], 1)
                self.assertGreaterEqual(metrics['transaction_ms_p95'], 0)
                for stage in ('lock_wait', 'sql', 'commit'):
                    self.assertGreaterEqual(metrics[f'{stage}_ms_p95'], 0)
                with patch('backend.app.services.flow_service.time.monotonic', return_value=service._storage_samples[-1][0]+61):
                    self.assertEqual(service.storage_metrics()['batches'], 0)
            finally:
                service.close()

    def test_snapshot_transaction_rolls_back_and_can_recover(self):
        with tempfile.TemporaryDirectory() as folder:
            service = FlowService(db_path=Path(folder)/'flows.db', persistent_writer=True)
            try:
                service.ingest(packet())
                with self.assertRaises(RuntimeError):
                    with service._snapshot_transaction({}) as conn:
                        conn.execute('DELETE FROM flows')
                        raise RuntimeError('abort transaction')
                with closing(sqlite3.connect(service.db_path)) as reader:
                    self.assertEqual(reader.execute('SELECT COUNT(*) FROM flows').fetchone()[0], 1)
                service.ingest(packet(id='pkt-2'))
                self.assertEqual(service.storage_metrics()['batches'], 2)
            finally:
                service.close()

    def test_live_summary_defers_details_without_losing_stored_evidence(self):
        engine = FlowEngine()
        row = packet(summary='TLS packet')
        snapshot = engine.ingest(row, redact_snapshot=True, live_summary=True)
        self.assertTrue(snapshot['details_deferred'])
        self.assertEqual(snapshot['sample_packets'], [])
        self.assertEqual(snapshot['sample_packets_total'], 1)
        self.assertTrue(snapshot['sample_packets_truncated'])
        full = engine.get_flow(flow_id_for(row))
        self.assertEqual(len(full['sample_packets']), 1)
        self.assertTrue(full['timeline'])
        engine.ingest(packet(id='pkt-2'), redact_snapshot=True, live_summary=True)
        full = engine.get_flow(flow_id_for(row))
        self.assertEqual(full['packets_count'], 2)
        self.assertEqual(snapshot['packets_count'], 1)

    def test_live_summary_nested_state_is_detached_and_redacted(self):
        engine = FlowEngine()
        row = packet(service_reasons=['token=secret-value'])
        summary = engine.ingest(row, redact_snapshot=True, live_summary=True)
        self.assertNotIn('secret-value', str(summary))
        summary['alert_counts']['critical'] = 99
        summary['risk_reasons'].append('caller mutation')
        stored = engine.get_flow(flow_id_for(row))
        self.assertNotEqual(stored['alert_counts'].get('critical'), 99)
        self.assertNotIn('caller mutation', stored['risk_reasons'])

    def test_live_snapshot_redaction_does_not_hold_engine_lock(self):
        import core.flow_engine as module
        engine = FlowEngine()
        original = module.redact_sensitive_data
        lock_states = []
        def inspect(value):
            lock_states.append(engine._lock._is_owned())
            return original(value)
        with patch.object(module, 'redact_sensitive_data', side_effect=inspect):
            snapshot = engine.ingest(packet(), redact_snapshot=True, compact_snapshot=True)
        self.assertEqual(lock_states, [False])
        before = json.dumps(snapshot, sort_keys=True)
        engine.ingest(packet(id='pkt-2', length=999), redact_snapshot=True, compact_snapshot=True)
        self.assertEqual(json.dumps(snapshot, sort_keys=True), before)

    def test_destination_domain_survives_packets_without_repeated_sni(self):
        engine = FlowEngine()
        first = packet(destination_domain="example.net", destination_domain_source="TLS SNI")
        engine.ingest(first)
        engine.ingest(packet(id="pkt-2", destination_domain="other.example.net",
                             destination_domain_source="DNS answer (correlated)"))
        flow = engine.get_flow(flow_id_for(first))
        self.assertEqual(flow["destination_domain"], "example.net")
        self.assertEqual(flow["destination_domain_source"], "TLS SNI")

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
    def test_batched_snapshots_preserve_order_and_redact_across_chunks(self):
        engine = FlowEngine()
        identifiers = []
        for index in range(33):
            row = packet(id=f"pkt-{index}", sport=53000 + index,
                         summary="Authorization: Bearer private-secret")
            identifiers.append(engine.ingest(row)["flow_id"])
        snapshots = engine.snapshot_flows(identifiers)
        self.assertEqual([row["flow_id"] for row in snapshots], identifiers)
        self.assertNotIn("private-secret", str(snapshots))

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
