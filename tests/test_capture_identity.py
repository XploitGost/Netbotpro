import os
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from core.capture.identity import valid_capture_event_id
from core.capture.journal import CaptureJournal
from core.netbotpro_logging import config, storage


EVENT = 'cap-v1:' + 'a' * 32 + ':1:0'


class CaptureIdentityTests(unittest.TestCase):
    def test_only_versioned_occurrence_ids_are_recognized(self):
        self.assertEqual(valid_capture_event_id(EVENT), EVENT)
        for value in (None, 42, '', 'mem-pkt-1', EVENT + '\n', EVENT.upper(),
                      'cap-v1:' + 'a' * 32 + ':0:0', 'cap-v1:' + 'a' * 100 + ':1:0'):
            self.assertIsNone(valid_capture_event_id(value))

    def history(self, path):
        return patch.multiple(config, DB_PATH=str(path), _CONN=None, PERSIST_LOGS=True)

    def test_reopen_deduplicates_only_stable_packet_occurrences(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'history.db'
            with self.history(path):
                conn = config.get_conn()
                try:
                    rows = [{'capture_event_id': EVENT, 'capture_id': EVENT, 'ts': '1'}]
                    with patch.object(storage, 'is_persist_enabled', return_value=True):
                        result = storage.insert_batch(rows, [])
                        self.assertEqual(result['status'], 'committed')
                        self.assertEqual(result['packets_inserted'], 1)
                finally:
                    conn.close()
            with self.history(path):
                conn = config.get_conn()
                try:
                    with patch.object(storage, 'is_persist_enabled', return_value=True):
                        replay = storage.insert_batch(rows, [])
                        self.assertEqual(replay['status'], 'committed')
                        self.assertEqual(replay['packets_inserted'], 0)
                        result = storage.insert_batch([
                            {'capture_event_id': EVENT[:-1] + '1', 'ts': '1'},
                            {'capture_event_id': EVENT.replace('a' * 32, 'b' * 32), 'ts': '1'},
                            {'capture_id': 'mem-pkt-1', 'ts': '1'},
                            {'capture_id': 'mem-pkt-1', 'ts': '1'},
                            {'capture_event_id': 'invalid', 'ts': '1'},
                            {'capture_event_id': 'invalid', 'ts': '1'},
                        ], [])
                    self.assertEqual(result['packets_inserted'], 6)
                    self.assertEqual(conn.execute('SELECT COUNT(*) FROM packets').fetchone()[0], 7)
                finally:
                    conn.close()

    def test_packet_conflict_does_not_suppress_an_independent_alert(self):
        with tempfile.TemporaryDirectory() as folder, self.history(Path(folder)/'history.db'):
            conn = config.get_conn()
            try:
                with patch.object(storage, 'is_persist_enabled', return_value=True):
                    storage.insert_batch([{'capture_event_id': EVENT}], [])
                    result = storage.insert_batch([{'capture_event_id': EVENT}], [{'packet_id': EVENT}])
                self.assertEqual(result['packets_inserted'], 0)
                self.assertEqual(result['alerts_inserted'], 1)
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0], 1)
            finally:
                conn.close()

    def test_disabled_storage_does_not_claim_inserted_rows(self):
        with patch.object(storage, 'is_persist_enabled', return_value=False), \
             patch.object(storage, 'get_conn') as connection:
            result = storage.insert_batch([{'capture_event_id': EVENT}], [{}])
        connection.assert_not_called()
        self.assertEqual(result['packets_inserted'], 0)
        self.assertEqual(result['alerts_inserted'], 0)
        self.assertEqual(result['status'], 'disabled')

    def test_retention_deletion_does_not_create_permanent_tombstones(self):
        with tempfile.TemporaryDirectory() as folder, self.history(Path(folder)/'history.db'):
            conn = config.get_conn()
            try:
                with patch.object(storage, 'is_persist_enabled', return_value=True):
                    storage.insert_batch([{'capture_event_id': EVENT}], [])
                    conn.execute('DELETE FROM packets WHERE capture_event_id=?', (EVENT,))
                    conn.commit()
                    self.assertEqual(storage.insert_batch([{'capture_event_id': EVENT}], [])['packets_inserted'], 1)
            finally:
                conn.close()

    @unittest.skipUnless(os.name == 'nt', 'DPAPI journal requires Windows')
    def test_legacy_journal_gets_one_stable_namespace_without_rewriting_payload(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'capture.db'
            journal = CaptureJournal(path)
            journal.append([{'sequence': 1}])
            journal.close()
            with closing(sqlite3.connect(path)) as conn, conn:
                payload = conn.execute('SELECT payload FROM batches').fetchone()[0]
                conn.execute('DROP TABLE journal_identity')
            upgraded = CaptureJournal(path)
            identity = upgraded.first()[1][0]['capture_event_id']
            upgraded.close()
            reopened = CaptureJournal(path)
            try:
                self.assertEqual(reopened.first()[1][0]['capture_event_id'], identity)
                self.assertEqual(reopened._db.execute('SELECT payload FROM batches').fetchone()[0], payload)
            finally:
                reopened.close()

    @unittest.skipUnless(os.name == 'nt', 'DPAPI journal requires Windows')
    def test_corrupt_namespace_is_not_silently_replaced(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'capture.db'
            journal = CaptureJournal(path)
            journal.append([{'sequence': 1}])
            journal.close()
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.execute("UPDATE journal_identity SET namespace='invalid'")
            with self.assertRaisesRegex(ValueError, 'Invalid journal identity'):
                CaptureJournal(path)
            with closing(sqlite3.connect(path)) as conn, conn:
                self.assertEqual(conn.execute('SELECT namespace FROM journal_identity').fetchone()[0], 'invalid')
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM batches').fetchone()[0], 1)

    def test_schema_upgrade_preserves_old_duplicate_capture_ids(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'history.db'
            conn = sqlite3.connect(path)
            columns = [column for column in storage._PACKET_COLUMNS if column != 'capture_event_id']
            conn.execute('CREATE TABLE packets (id INTEGER PRIMARY KEY,' +
                         ','.join(f'{column} TEXT' for column in columns) + ')')
            conn.executemany('INSERT INTO packets(capture_id) VALUES (?)', [('mem-pkt-1',)] * 2)
            conn.commit()
            conn.close()
            with self.history(path):
                conn = config.get_conn()
                try:
                    self.assertEqual(conn.execute('SELECT COUNT(*) FROM packets').fetchone()[0], 2)
                    self.assertEqual(conn.execute('SELECT COUNT(capture_event_id) FROM packets').fetchone()[0], 0)
                finally:
                    conn.close()

    def test_unrelated_constraint_failure_rolls_back_packet_insert(self):
        with tempfile.TemporaryDirectory() as folder, self.history(Path(folder)/'history.db'):
            conn = config.get_conn()
            try:
                conn.execute("CREATE TRIGGER reject_alert BEFORE INSERT ON alerts BEGIN SELECT RAISE(ABORT,'test'); END")
                conn.commit()
                with patch.object(storage, 'is_persist_enabled', return_value=True):
                    with self.assertRaises(sqlite3.IntegrityError):
                        storage.insert_batch([{'capture_event_id': EVENT}], [{'packet_id': EVENT}])
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM packets').fetchone()[0], 0)
            finally:
                conn.close()

    @unittest.skipUnless(os.name == 'nt', 'DPAPI journal requires Windows')
    def test_history_commit_before_ack_can_replay_without_duplicate_packet(self):
        with tempfile.TemporaryDirectory() as folder:
            journal_path, history_path = Path(folder)/'capture.db', Path(folder)/'history.db'
            journal = CaptureJournal(journal_path)
            journal.append([{'sequence': 1}, {'sequence': 1}])
            original = journal.first()
            with self.history(history_path):
                conn = config.get_conn()
                try:
                    with patch.object(storage, 'is_persist_enabled', return_value=True):
                        self.assertEqual(storage.insert_batch(original[1], [])['packets_inserted'], 2)
                finally:
                    conn.close()
            # Model the restart window after history commit but before journal ack.
            journal.close()
            recovered = CaptureJournal(journal_path)
            try:
                replay = recovered.first()
                self.assertEqual(replay, original)
                with self.history(history_path):
                    conn = config.get_conn()
                    try:
                        with patch.object(storage, 'is_persist_enabled', return_value=True):
                            self.assertEqual(storage.insert_batch(replay[1], [])['packets_inserted'], 0)
                        self.assertEqual(conn.execute('SELECT COUNT(*) FROM packets').fetchone()[0], 2)
                    finally:
                        conn.close()
                recovered.acknowledge(replay[0])
                self.assertIsNone(recovered.first())
            finally:
                recovered.close()

    @unittest.skipUnless(os.name == 'nt', 'DPAPI journal requires Windows')
    def test_journal_identity_survives_reopen_and_distinguishes_occurrences(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'capture.db'
            first = CaptureJournal(path)
            second = CaptureJournal(path)
            other = CaptureJournal(Path(folder)/'other.db')
            try:
                rows = [{'sequence': 1}, {'sequence': 1}]
                first.append(rows)
                original = first.first()
                self.assertEqual(second.first(), original)
                self.assertNotEqual(original[1][0]['capture_event_id'], original[1][1]['capture_event_id'])
                self.assertNotIn('capture_event_id', rows[0])
                other.append(rows)
                self.assertNotEqual(other.first()[1][0]['capture_event_id'], original[1][0]['capture_event_id'])
            finally:
                first.close()
                second.close()
                other.close()
            recovered = CaptureJournal(path)
            try:
                self.assertEqual(recovered.first(), original)
                recovered.acknowledge(original[0])
                recovered.append(rows)
                self.assertNotEqual(recovered.first()[1][0]['capture_event_id'], original[1][0]['capture_event_id'])
            finally:
                recovered.close()
