import unittest
from unittest.mock import Mock, patch

from backend.app.services.batch_persistence import BatchPersistenceWriter
from backend.app.services.persistence_contracts import PersistenceWriteOutcome
from backend.app.services.sniffer_persistence import SnifferPersistence
from core.netbotpro_logging import storage


class HistoryWriteOutcomeTests(unittest.TestCase):
    @patch('backend.app.services.sniffer_persistence.is_persist_enabled', return_value=True)
    def test_disabled_storage_does_not_report_queued_record_as_written(self, _enabled):
        persistence = SnifferPersistence(batch_size=100, flush_interval=60, max_retries=0)
        try:
            with patch.object(storage, 'is_persist_enabled', return_value=False):
                persistence.persist({'id': 'packet-1'}, [])
                self.assertFalse(persistence.flush())
            metrics = persistence.stats()
            self.assertEqual(metrics['events_written_total'], 0)
            self.assertEqual(metrics['events_skipped_total'], 1)
            self.assertEqual(metrics['events_failed_total'], 0)
            self.assertEqual(metrics['retry_total'], 0)
            self.assertEqual(metrics['health'], 'healthy')
            self.assertTrue(persistence.flush())
            self.assertEqual(persistence.stats()['skipped_writes'], 1)
        finally:
            persistence.close()

    @patch('backend.app.services.sniffer_persistence.insert_batch')
    def test_unavailable_history_is_retried_before_flow_without_false_progress(self, insert):
        insert.side_effect = [
            {'status': 'unavailable', 'retries': 0, 'packets_inserted': 0, 'alerts_inserted': 0},
            {'status': 'committed', 'retries': 0, 'packets_inserted': 1, 'alerts_inserted': 1},
        ]
        flow = Mock()
        persistence = SnifferPersistence(flow_writer=flow, max_retries=1, retry_backoff_sec=0)
        grouped = {kind: [{'payload': {}}] for kind in ('packet_record', 'alert_record', 'flow_record')}
        try:
            with patch.object(persistence, '_run_retention_cleanup'):
                outcome = persistence._batch_writer._execute_with_retry(grouped)
            self.assertEqual(outcome, PersistenceWriteOutcome(3))
            self.assertEqual(insert.call_count, 2)
            flow.assert_called_once()
            self.assertEqual(persistence.stats()['persisted_packets'], 1)
            self.assertEqual(persistence.stats()['retry_total'], 1)
        finally:
            persistence.close()

    @patch('backend.app.services.sniffer_persistence.insert_batch',
           return_value={'status': 'disabled', 'retries': 0, 'packets_inserted': 0, 'alerts_inserted': 0})
    def test_disabled_history_does_not_hide_successful_flow_or_repeat_on_flow_retry(self, insert):
        flow = Mock(side_effect=[OSError('temporary'), None])
        persistence = SnifferPersistence(flow_writer=flow, max_retries=1, retry_backoff_sec=0)
        grouped = {kind: [{'payload': {}}] for kind in ('packet_record', 'alert_record', 'flow_record')}
        try:
            with patch.object(persistence, '_run_retention_cleanup'):
                outcome = persistence._batch_writer._execute_with_retry(grouped)
            self.assertEqual(outcome, PersistenceWriteOutcome(1, 2))
            insert.assert_called_once()
            self.assertEqual(flow.call_count, 2)
            self.assertEqual(persistence.stats()['persisted_packets'], 0)
        finally:
            persistence.close()

    @patch('backend.app.services.sniffer_persistence.is_persist_enabled', return_value=True)
    @patch('backend.app.services.sniffer_persistence.insert_batch',
           return_value={'status': 'committed', 'retries': 0, 'packets_inserted': 0, 'alerts_inserted': 0})
    def test_committed_duplicate_is_not_an_intentional_skip(self, insert, _enabled):
        persistence = SnifferPersistence(batch_size=100, flush_interval=60)
        try:
            persistence.persist({'id': 'packet-1'}, [])
            self.assertTrue(persistence.flush())
            metrics = persistence.stats()
            self.assertEqual(metrics['events_written_total'], 1)
            self.assertEqual(metrics['events_skipped_total'], 0)
            self.assertEqual(metrics['persisted_packets'], 0)
        finally:
            persistence.close()

    def test_typed_outcome_accounting_in_sync_and_worker_modes(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                writer = BatchPersistenceWriter(lambda grouped: PersistenceWriteOutcome(0, 1),
                    enabled=enabled, retry_max=0, batch_sizes={'packet_record': 100},
                    flush_ms={'packet_record': 60000})
                try:
                    self.assertEqual(writer.enqueue('packet_record', {}), enabled)
                    receipt = writer.flush_result()
                    self.assertEqual(receipt.succeeded, not enabled)
                    self.assertEqual(receipt.skipped_after, 1)
                    self.assertEqual(writer.metrics()['events_written_total'], 0)
                    self.assertEqual(writer.metrics()['events_skipped_total'], 1)
                    self.assertEqual(writer.metrics()['events_failed_total'], 0)
                finally:
                    writer.close()

    def test_incomplete_or_invalid_outcome_does_not_create_written_events(self):
        for values in ((-1, 0), (True, 0), (0, -1)):
            with self.assertRaises(ValueError):
                PersistenceWriteOutcome(*values)
        writer = BatchPersistenceWriter(lambda grouped: PersistenceWriteOutcome(0),
            enabled=False, retry_max=0)
        self.assertFalse(writer.enqueue('packet_record', {}))
        self.assertEqual(writer.metrics()['events_written_total'], 0)
        self.assertEqual(writer.metrics()['events_failed_total'], 1)

    def test_skips_do_not_clear_errors_or_create_success_latency_samples(self):
        write = Mock(side_effect=[OSError('private connection details'),
                                 PersistenceWriteOutcome(0, 1), PersistenceWriteOutcome(1)])
        writer = BatchPersistenceWriter(write, enabled=False, retry_max=0)
        self.assertFalse(writer.enqueue('packet_record', {}))
        self.assertFalse(writer.enqueue('packet_record', {}))
        metrics = writer.metrics()
        self.assertEqual(metrics['last_error'], 'OSError')
        self.assertEqual(metrics['events_skipped_total'], 1)
        self.assertEqual(metrics['events_written_total'], 0)
        self.assertEqual(len(writer._latencies), 0)
        self.assertEqual(writer._consecutive_failures, 1)
        self.assertNotIn('private connection', str(metrics))
        self.assertTrue(writer.enqueue('packet_record', {}))
        self.assertEqual(writer.metrics()['last_error'], '')
        self.assertEqual(len(writer._latencies), 1)

    @patch('backend.app.services.sniffer_persistence.is_persist_enabled', return_value=True)
    def test_missing_connection_is_not_a_successful_write(self, _enabled):
        persistence = SnifferPersistence(batch_size=100, flush_interval=60, max_retries=0)
        try:
            with patch.object(storage, 'is_persist_enabled', return_value=True), \
                 patch.object(storage, 'get_conn', return_value=None):
                persistence.persist({'id': 'packet-1'}, [])
                self.assertFalse(persistence.flush())
            metrics = persistence.stats()
            self.assertEqual(metrics['events_written_total'], 0)
            self.assertEqual(metrics['events_failed_total'], 1)
        finally:
            persistence.close()
