from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from backend.app.repositories.history_repository import _normalize_alpn
from core.netbotpro_logging import config, storage


class HistoryAlpnStorageTests(unittest.TestCase):
    def test_alpn_packet_and_alert_sequences_round_trip_without_mutation(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.multiple(config, DB_PATH=str(Path(folder) / 'history.db'), _CONN=None, PERSIST_LOGS=True):
            connection = config.get_conn()
            try:
                for value, expected in (([], []), (['h2', 'http/1.1'], ['h2', 'http/1.1']),
                                        (('h3',), ['h3']), ('h2, http/1.1', ['h2', 'http/1.1']), (None, [])):
                    with self.subTest(value=value):
                        packet, alert = {'tls_alpn': value}, {'tls_alpn': value}
                        before = deepcopy((packet, alert))
                        receipt = storage.insert_batch([packet], [alert])
                        self.assertEqual(receipt['status'], 'committed')
                        for table in ('packets', 'alerts'):
                            stored = connection.execute(f'SELECT tls_alpn FROM {table} ORDER BY id DESC LIMIT 1').fetchone()[0]
                            self.assertEqual(_normalize_alpn(stored), expected)
                        self.assertEqual((packet, alert), before)
            finally:
                connection.close()

    def test_unrelated_unsupported_fields_still_fail_and_roll_back_the_group(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.multiple(config, DB_PATH=str(Path(folder) / 'history.db'), _CONN=None, PERSIST_LOGS=True):
            connection = config.get_conn()
            try:
                import sqlite3
                with self.assertRaises(sqlite3.ProgrammingError):
                    storage.insert_batch([{'tls_alpn': ['h2']}], [{'detail': {'unsupported': True}}])
                for table in ('packets', 'alerts'):
                    self.assertEqual(connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0], 0)
            finally:
                connection.close()
