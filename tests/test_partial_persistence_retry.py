import sqlite3
import unittest
from unittest.mock import Mock, patch

from backend.app.services.sniffer_persistence import SnifferPersistence
from core.netbotpro_logging import storage


class PartialPersistenceRetryTests(unittest.TestCase):
    @staticmethod
    def grouped():
        return {
            'packet_record': [{'payload': {'capture_id': 'packet-1', 'ts': '1'}}],
            'alert_record': [{'payload': {'packet_id': 'packet-1', 'ts': '1'}}],
            'flow_record': [{'payload': {'flow_id': 'flow-1'}}],
        }

    @patch('backend.app.services.sniffer_persistence.insert_batch')
    def test_history_failure_retries_before_flow_and_new_batches_do_not_share_progress(self, insert):
        calls = []
        def history(packets, alerts):
            calls.append('history')
            if len(calls) == 1:
                raise OSError('temporary')
            return {'retries': 2}
        insert.side_effect = history
        persistence = SnifferPersistence(flow_writer=lambda rows: calls.append('flow'),
            max_retries=1, retry_backoff_sec=0)
        try:
            with patch.object(persistence, '_run_retention_cleanup'):
                retries = persistence._batch_writer._write_with_retry(self.grouped())
                self.assertEqual(retries, 2)
                self.assertEqual(calls, ['history', 'history', 'flow'])
                persistence._batch_writer._write_with_retry(self.grouped())
            self.assertEqual(calls, ['history', 'history', 'flow', 'history', 'flow'])
            self.assertEqual(persistence.stats()['persisted_packets'], 2)
        finally:
            persistence.close()

    @patch('backend.app.services.sniffer_persistence.insert_batch', return_value={'retries': 0})
    def test_terminal_flow_failure_preserves_confirmed_history_counts(self, insert):
        flow = Mock(side_effect=OSError('flow unavailable'))
        persistence = SnifferPersistence(flow_writer=flow, max_retries=1, retry_backoff_sec=0)
        try:
            with self.assertRaises(OSError):
                persistence._batch_writer._write_with_retry(self.grouped())
            insert.assert_called_once()
            self.assertEqual(flow.call_count, 2)
            self.assertEqual(persistence.stats()['persisted_packets'], 1)
            self.assertEqual(persistence.stats()['persisted_alerts'], 1)
        finally:
            persistence.close()

    @patch('backend.app.services.sniffer_persistence.insert_batch', return_value={'retries': 0})
    def test_failure_after_both_writers_return_does_not_replay_either(self, insert):
        flow = Mock()
        persistence = SnifferPersistence(flow_writer=flow, max_retries=1, retry_backoff_sec=0)
        try:
            with patch.object(persistence, '_run_retention_cleanup', side_effect=[OSError(), None]):
                persistence._batch_writer._write_with_retry(self.grouped())
            insert.assert_called_once()
            flow.assert_called_once()
        finally:
            persistence.close()

    @patch('backend.app.services.sniffer_persistence.insert_batch')
    def test_empty_categories_do_not_invoke_missing_writers(self, insert):
        persistence = SnifferPersistence(max_retries=1, retry_backoff_sec=0)
        try:
            with patch.object(persistence, '_run_retention_cleanup'):
                persistence._batch_writer._write_with_retry({})
            insert.assert_not_called()
            self.assertEqual(persistence.stats()['persisted_packets'], 0)
        finally:
            persistence.close()

    def test_flow_retry_does_not_duplicate_committed_packet_and_alert_rows(self):
        connection = sqlite3.connect(':memory:', check_same_thread=False)
        for table, columns in (('packets', storage._PACKET_COLUMNS),
                               ('alerts', storage._ALERT_COLUMNS)):
            connection.execute(f'CREATE TABLE {table} (' +
                ','.join(f'{column} TEXT' for column in columns) + ')')
        flow_calls = []
        def flaky_flow(rows):
            flow_calls.append(rows)
            if len(flow_calls) == 1:
                raise OSError('flow database temporarily unavailable')
        persistence = SnifferPersistence(flow_writer=flaky_flow,
            max_retries=1, retry_backoff_sec=0)
        try:
            with patch.object(storage, 'get_conn', return_value=connection), \
                 patch.object(storage, 'is_persist_enabled', return_value=True), \
                 patch.object(persistence, '_run_retention_cleanup'):
                persistence._batch_writer._write_with_retry(self.grouped())
            self.assertEqual(len(flow_calls), 2)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM packets').fetchone()[0], 1)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0], 1)
            self.assertEqual(persistence.stats()['persisted_packets'], 1)
        finally:
            persistence.close()
            connection.close()
