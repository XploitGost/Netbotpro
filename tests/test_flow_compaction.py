import json
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from core.flow_engine import FlowEngine
from core.flow_compaction import PACKED_FIELD, pack_flow
from backend.app.services.flow_service import FlowService


def packet(index, length=100):
    return dict(id=f'p-{index}-{length}', ts='2026-11-09T12:00:00Z',
                src='10.0.0.5', dst='8.8.8.8', sport=40000 + index, dport=443,
                proto='TCP', length=length, direction='OUTGOING', tls_sni='example.test',
                service_attribution={'token': 'DONOTEXPOSE_FLOW_TOKEN_17'})


class FlowCompactionTests(unittest.TestCase):
    def test_monitoring_reports_memory_pressure_without_packet_loss(self):
        from backend.app.services.monitoring_service import build_monitoring_metrics
        result = build_monitoring_metrics(sniffer_state={}, flow_summary={}, observability={
            'flow_memory': {'enabled': True, 'hot_flows': 5000, 'compressed_flows': 100,
                            'hot_target': 2048, 'health': 'degraded',
                            'pressure_reasons': ['flow_memory_hot_pressure', {'private': 'ignored'}]}})
        self.assertEqual(result['flow_memory']['hot_flows'], 5000)
        self.assertEqual(result['packet_queue']['dropped_total'], 0)
        self.assertEqual(result['health'], 'degraded')
        self.assertNotIn('private', str(result))

    def populated(self):
        ticks = [0]
        engine = FlowEngine(clock=lambda: ticks[0])
        identifiers = []
        for index in range(6):
            result = engine.ingest(packet(index), [{'id': f'a-{index}', 'severity': 'high', 'detail': 'test'}])
            identifiers.append(result['flow_id'])
        ticks[0] = 200
        return engine, ticks, identifiers

    def test_all_public_views_and_filters_are_unchanged(self):
        engine, _, ids = self.populated()
        expected = [engine.get_flow(identifier) for identifier in ids]
        full_summary = engine.summary()
        compact_summary = engine.summary(compact_top=True)
        conversations = engine.conversations()
        conversation_detail = engine.get_conversation(conversations[0]['conversation_id'])
        snapshots = engine.snapshot_flows(ids)
        queries = ({}, {'protocol': 'TLS'}, {'risk': 'high'}, {'port': 443},
                   {'src_ip': '10.0.0.5'}, {'direction': 'outbound'}, {'has_alerts': True},
                   {'sort': 'alerts'}, {'sort': 'bytes'}, {'sort': 'packets'}, {'limit': 2},
                   {'since': '2026-11-09'})
        lists = [engine.list_flows(**query) for query in queries]
        monitoring = engine.monitoring_summary()
        self.assertEqual(engine.compact_idle(hot_target=1, idle_seconds=120), 5)
        self.assertEqual([engine.get_flow(identifier) for identifier in ids], expected)
        self.assertEqual(engine.summary(), full_summary)
        self.assertEqual(engine.summary(compact_top=True), compact_summary)
        self.assertEqual(engine.conversations(), conversations)
        self.assertEqual(engine.get_conversation(conversations[0]['conversation_id']), conversation_detail)
        self.assertEqual(engine.snapshot_flows(ids), snapshots)
        self.assertEqual([engine.list_flows(**query) for query in queries], lists)
        self.assertEqual(engine.monitoring_summary(), monitoring)
        self.assertNotIn('_cold_', str(engine.list_flows()))
        self.assertEqual(engine.memory_stats()['compressed_flows'], 5)

    def test_traffic_restores_full_counter_and_alert_identity(self):
        engine, _, ids = self.populated()
        expected = engine.get_flow(ids[0])
        engine.compact_idle(hot_target=1, idle_seconds=120)
        actual = engine.ingest(packet(0, 150), [{'id': 'a-0', 'severity': 'high'}])
        self.assertEqual(actual['packets_count'], 2)
        self.assertEqual(actual['bytes_total'], 250)
        self.assertEqual(actual['first_seen'], expected['first_seen'])
        self.assertEqual(actual['related_alert_ids'], ['a-0'])
        self.assertEqual(actual['alert_counts']['high'], 2)
        self.assertEqual(engine.memory_stats()['restorations_total'], 1)
        self.assertNotIn(PACKED_FIELD, engine._flows[ids[0]])

    def test_mutating_a_public_cold_view_cannot_change_stored_evidence(self):
        engine, _, ids = self.populated()
        expected = engine.get_flow(ids[0])
        engine.compact_idle(hot_target=1, idle_seconds=120)
        result = engine.get_flow(ids[0])
        result['timeline'].clear()
        result['sample_packets'][0]['metadata']['sni'] = 'changed'
        result['alert_counts'].clear()
        self.assertEqual(engine.get_flow(ids[0]), expected)

    def test_unsupported_metadata_stays_hot_without_type_changes(self):
        ticks = [0]
        engine = FlowEngine(clock=lambda: ticks[0])
        row = packet(0)
        row['service_attribution'] = {'typed_value': ('one', 'two')}
        expected = engine.ingest(row)
        engine.ingest(packet(1))
        ticks[0] = 200
        self.assertEqual(engine.compact_idle(hot_target=1, idle_seconds=120), 0)
        self.assertEqual(engine.get_flow(expected['flow_id']), expected)
        self.assertEqual(engine.memory_stats()['unsupported_compactions_total'], 1)

    def test_active_flows_are_not_compacted_and_reset_releases_cold_state(self):
        engine, ticks, ids = self.populated()
        engine.ingest(packet(0))
        self.assertEqual(engine.compact_idle(hot_target=1, idle_seconds=120), 5)
        self.assertNotIn(PACKED_FIELD, engine._flows[ids[0]])
        engine.reset()
        self.assertEqual(engine.memory_stats()['compressed_bytes'], 0)
        self.assertEqual(engine.memory_stats()['hot_flows'], 0)
        self.assertEqual(engine.memory_stats()['total_flows'], 0)

    def test_concurrent_traffic_prevents_stale_compaction_commit(self):
        engine, _, ids = self.populated()
        encoding, release = threading.Event(), threading.Event()
        def delayed(flow):
            encoding.set()
            release.wait(5)
            return pack_flow(flow)
        worker = threading.Thread(target=lambda: engine.compact_idle(hot_target=1, idle_seconds=120, batch_size=1))
        try:
            with patch('core.flow_engine.pack_flow', side_effect=delayed):
                worker.start()
                self.assertTrue(encoding.wait(1))
                engine.ingest(packet(0, 150))
                release.set()
                worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(engine.get_flow(ids[0])['packets_count'], 2)
            self.assertEqual(engine.memory_stats()['compressed_flows'], 0)
        finally:
            release.set()
            worker.join(5)

    def test_reset_during_compression_cannot_resurrect_old_flows(self):
        engine, _, _ = self.populated()
        def reset_before_pack(flow):
            engine.reset()
            engine.ingest(packet(0, 200))
            return pack_flow(flow)
        with patch('core.flow_engine.pack_flow', side_effect=reset_before_pack):
            engine.compact_idle(hot_target=1, idle_seconds=120, batch_size=1)
        self.assertEqual(engine.monitoring_summary()['total_flows'], 1)
        self.assertEqual(engine.list_flows()[0]['bytes_total'], 200)
        self.assertEqual(engine.memory_stats()['compressed_flows'], 0)

    def test_sqlite_snapshots_and_privacy_are_preserved_for_cold_flows(self):
        engine, _, ids = self.populated()
        engine.compact_idle(hot_target=1, idle_seconds=120)
        with tempfile.TemporaryDirectory() as folder:
            service = FlowService(engine=engine, db_path=Path(folder) / 'f.db', memory_compaction=False)
            try:
                service.write_live_snapshots([{'flow_id': identifier} for identifier in ids])
                with closing(sqlite3.connect(service.db_path)) as connection:
                    rows = [json.loads(row[0]) for row in connection.execute('SELECT snapshot_json FROM flows')]
                self.assertEqual(sum(row['packets_count'] for row in rows), 6)
                self.assertTrue(all(row['timeline'] and row['sample_packets'] for row in rows))
                self.assertNotIn('_cold_', str(rows))
                self.assertNotIn('DONOTEXPOSE_FLOW_TOKEN_17', str(rows))
                self.assertNotIn('DONOTEXPOSE_FLOW_TOKEN_17', str(service.get_flow(ids[0])))
            finally:
                service.close()

    def test_background_worker_is_joined(self):
        with tempfile.TemporaryDirectory() as folder:
            service = FlowService(db_path=Path(folder) / 'f.db', memory_compaction=True)
            try:
                self.assertTrue(service.memory_stats()['worker_alive'])
                self.assertTrue(service.memory_stats()['enabled'])
            finally:
                service.close()
            self.assertFalse(service.memory_stats()['worker_alive'])

    def test_worker_routine_uses_configured_idle_compaction(self):
        engine, _, _ = self.populated()
        with tempfile.TemporaryDirectory() as folder:
            service = FlowService(engine=engine, db_path=Path(folder) / 'f.db', memory_compaction=False)
            try:
                service._hot_target = 1
                service._cold_after = 120
                with patch.object(service._memory_stop, 'wait', side_effect=[False, True]):
                    service._compact_memory()
                self.assertEqual(service.memory_stats()['compressed_flows'], 5)
                self.assertEqual(service.memory_stats()['errors_total'], 0)
            finally:
                service.close()

    def test_cold_query_deserialization_does_not_hold_ingest_lock(self):
        from core.flow_compaction import expand_flow
        engine, _, ids = self.populated()
        engine.compact_idle(hot_target=1, idle_seconds=120)
        reading, release, ingested = threading.Event(), threading.Event(), threading.Event()
        def delayed(flow):
            reading.set()
            release.wait(5)
            return expand_flow(flow)
        reader = threading.Thread(target=lambda: engine.get_flow(ids[0]))
        writer = threading.Thread(target=lambda: (engine.ingest(packet(5)), ingested.set()))
        try:
            with patch('core.flow_engine.expand_flow', side_effect=delayed):
                reader.start()
                self.assertTrue(reading.wait(1))
                writer.start()
                self.assertTrue(ingested.wait(1), 'Query decoding held the analysis lock')
                release.set()
                reader.join(5)
                writer.join(5)
        finally:
            release.set()
            if reader.ident is not None:
                reader.join(5)
            if writer.ident is not None:
                writer.join(5)

    def test_compaction_failure_is_visible_without_deleting_flows(self):
        engine, _, _ = self.populated()
        with tempfile.TemporaryDirectory() as folder:
            service = FlowService(engine=engine, db_path=Path(folder) / 'f.db', memory_compaction=False)
            try:
                with patch.object(service._memory_stop, 'wait', side_effect=[False, True]), \
                     patch.object(engine, 'compact_idle', side_effect=RuntimeError('private details')):
                    service._compact_memory()
                metrics = service.memory_stats()
                self.assertEqual(metrics['last_error'], 'RuntimeError')
                self.assertEqual(metrics['health'], 'degraded')
                self.assertEqual(metrics['errors_total'], 1)
                self.assertEqual(metrics['total_flows'], 6)
                self.assertNotIn('private', str(metrics))
            finally:
                service.close()


if __name__ == '__main__':
    unittest.main()
