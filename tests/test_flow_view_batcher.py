import unittest
import threading
import os
import sqlite3
import json
import tempfile
from pathlib import Path
from contextlib import closing
from unittest.mock import patch
from backend.app.services.flow_view_batcher import FlowViewBatcher


class FlowViewBatcherTests(unittest.TestCase):
    def test_monitoring_distinguishes_view_pressure_from_packet_drops(self):
        from backend.app.services.monitoring_service import build_monitoring_metrics
        result = build_monitoring_metrics(sniffer_state={'running': True}, flow_summary={},
                                         observability={'flow_views': {
                                             'capacity': 2, 'pending': 2, 'worker_alive': True,
                                             'capacity_evictions_total': 8, 'health': 'degraded',
                                             'pressure_reasons': ['flow_view_capacity_evictions', {'private': 'ignored'}, 42]}})
        self.assertEqual(result['flow_views']['capacity_evictions_total'], 8)
        self.assertEqual(result['packet_queue']['dropped_total'], 0)
        self.assertIn('flow_view_capacity_evictions', result['pressure_reasons'])
        self.assertEqual(result['health'], 'degraded')
        self.assertNotIn('private', str(result))

    def test_optional_view_eviction_preserves_analysis_packets_and_persisted_flows(self):
        from backend.app.services.event_bus import EventBus
        from backend.app.services.flow_service import FlowService
        from backend.app.services.sniffer_service import SnifferService
        with tempfile.TemporaryDirectory() as folder, \
             patch.dict(os.environ, {'NETBOT_STABILITY_RECORDING': '0', 'NETBOT_PROFILE_STAGES': '0'}), \
             patch('backend.app.services.sniffer_persistence.is_persist_enabled', return_value=False), \
             patch('backend.app.services.sniffer_persistence.cleanup_retention'):
            path = Path(folder) / 'flows.db'
            bus = EventBus()
            service = SnifferService(bus, flow_service=FlowService(db_path=path))
            service._flow_views.close()
            service._flow_views = FlowViewBatcher(service._record_flow_view, interval=60, capacity=2)
            try:
                for index in range(100):
                    service._process_packet({'id': f'test-{index}', 'src': '192.0.2.1',
                                             'dst': '198.51.100.2', 'sport': 40000 + index % 10,
                                             'dport': 443, 'proto': 'TCP', 'length': 60,
                                             'ts': '2026-11-09T00:00:00Z'})
                self.assertEqual(service.get_state()['total_packets'], 100)
                self.assertEqual(len(service.recent_packets()), 100)
                self.assertEqual(service._flow_views.stats()['capacity_evictions_total'], 98)
                self.assertEqual(service.flow_service.monitoring_summary()['total_flows'], 10)
                self.assertTrue(service._persistence.flush(5))
                with closing(sqlite3.connect(path)) as connection:
                    self.assertEqual(connection.execute('SELECT count(*) FROM flows').fetchone()[0], 10)
                    packets = sum(json.loads(row[0])['packets_count']
                                  for row in connection.execute('SELECT snapshot_json FROM flows'))
                    self.assertEqual(packets, 100)
                self.assertEqual(service._persistence.stats()['events_dropped_total'], 0)
            finally:
                service.close()
                bus.close()

    def test_public_ring_redacts_internal_summary(self):
        from backend.app.services.live_ring_buffer import LiveRingBuffer
        from backend.app.services.sniffer_service import SnifferService
        service = object.__new__(SnifferService)
        service._live_ring_buffer = LiveRingBuffer()
        batcher = FlowViewBatcher(service._record_flow_view, interval=60)
        try:
            batcher.submit({'flow_id':'one', 'packets_count':12,
                            'service_reasons':['token=private-value'],
                            'metadata':{'payload_hex':'private-bytes'}})
            batcher.flush()
            rows = service._live_ring_buffer.recent_payloads('flow')
            self.assertEqual(rows[0]['packets_count'], 12)
            self.assertNotIn('private-value', str(rows))
            self.assertNotIn('private-bytes', str(rows))
        finally:
            batcher.close()

    def test_latest_view_coalesces_without_losing_final_counter(self):
        published = []
        batcher = FlowViewBatcher(published.append, interval=60)
        try:
            for count in range(100):
                batcher.submit({'flow_id':'one', 'packets_count':count+1})
            batcher.flush()
            self.assertEqual(published, [{'flow_id':'one','packets_count':100}])
            self.assertEqual(batcher.stats()['coalesced'], 99)
        finally:
            batcher.close()

    def test_capacity_evicts_only_oldest_optional_view_and_clear(self):
        published = []
        batcher = FlowViewBatcher(published.append, interval=60, capacity=2)
        try:
            for identifier in ('one','two','three'):
                batcher.submit({'flow_id':identifier})
            self.assertLessEqual(batcher.stats()['pending'], 2)
            self.assertEqual(published, [])
            self.assertEqual(batcher.stats()['capacity_evictions_total'], 1)
            self.assertEqual(list(batcher._pending), ['two', 'three'])
            batcher.clear()
            batcher.flush()
            self.assertEqual(published, [])
        finally:
            batcher.close()

    def test_slow_publisher_does_not_block_capture_owner_at_capacity(self):
        publishing, release, submitted = threading.Event(), threading.Event(), threading.Event()
        published = []
        def publish(row):
            publishing.set()
            release.wait(5)
            published.append(row)
        batcher = FlowViewBatcher(publish, interval=60, capacity=2)
        worker = threading.Thread(target=batcher.flush)
        submitter = threading.Thread(target=lambda: (batcher.submit({'flow_id': 'three'}), submitted.set()))
        try:
            batcher.submit({'flow_id': 'one'})
            batcher.submit({'flow_id': 'two'})
            worker.start()
            self.assertTrue(publishing.wait(1))
            submitter.start()
            self.assertTrue(submitted.wait(1), 'Capture owner waited for optional view publication')
            self.assertLessEqual(batcher.stats()['pending'], 2)
        finally:
            release.set()
            if submitter.ident is not None:
                submitter.join(5)
            if worker.ident is not None:
                worker.join(5)
            batcher.close()
        self.assertIn({'flow_id': 'three'}, published)

    def test_recently_updated_views_survive_and_pressure_expires(self):
        published = []
        batcher = FlowViewBatcher(published.append, interval=60, capacity=2)
        try:
            with patch('backend.app.services.flow_view_batcher.time.monotonic', return_value=100):
                batcher.submit({'flow_id': 'one', 'packets_count': 1})
                batcher.submit({'flow_id': 'two'})
                batcher.submit({'flow_id': 'one', 'packets_count': 2})
                batcher.submit({'flow_id': 'three'})
                self.assertEqual(list(batcher._pending), ['one', 'three'])
                self.assertEqual(batcher.stats()['health'], 'degraded')
            with patch('backend.app.services.flow_view_batcher.time.monotonic', return_value=161):
                self.assertEqual(batcher.stats()['health'], 'healthy')
                self.assertEqual(batcher.stats()['capacity_evictions_total'], 1)
            batcher.flush()
            self.assertEqual(published[0]['packets_count'], 2)
        finally:
            batcher.close()

    def test_publish_failure_retains_snapshot(self):
        published = []
        def publish(row):
            if not published:
                published.append('failed')
                raise RuntimeError('retry')
            published.append(row)
        batcher = FlowViewBatcher(publish, interval=60)
        try:
            batcher.submit({'flow_id':'one'})
            with self.assertRaises(RuntimeError):
                batcher.flush()
            self.assertEqual(batcher.stats()['pending'], 1)
            batcher.flush()
            self.assertEqual(published[-1], {'flow_id':'one'})
        finally:
            batcher.close()
