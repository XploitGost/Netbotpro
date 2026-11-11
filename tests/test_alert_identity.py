from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from backend.app.services.sniffer_detection_pipeline import SnifferDetectionPipeline
from backend.app.services.sniffer_persistence import SnifferPersistence
from core.alert_identity import alert_occurrence_id, custom_rule_key, valid_alert_event_id
from core.capture.journal import CaptureJournal
from core.ids_rules_engine import RuleEngine
from core.ids_signature import SignatureIDS
from core.netbotpro_logging import config, storage


EVENT = 'cap-v1:' + 'a' * 32 + ':1:0'


class Noop:
    def analyze(self, *args, **kwargs):
        return None
    analyze_packet = analyze
    enrich_alert = analyze


def pipeline(raw):
    instance = SnifferDetectionPipeline(settings_provider=lambda: {}, ids_sig=Noop(),
        ids_ml=Noop(), rule_engine=Noop(), scorer=Noop(), incidents=Noop())
    instance._detect_application_alerts = lambda packet: [dict(row) for row in raw]
    return instance


def alert(rule='app.test', version='1', **extra):
    return {'detection_rule_key': rule, 'detection_rule_version': version,
            'attack_type': 'Same title', 'score': 0.5, **extra}


def packet(event=EVENT):
    return {'id': event, 'capture_event_id': event, 'ts': '2026-11-11T12:00:00+00:00',
            'src': '192.0.2.1', 'dst': '198.51.100.1', 'proto': 'TCP', 'dport': 443}


@contextmanager
def history(path):
    with patch.multiple(config, DB_PATH=str(path), _CONN=None, PERSIST_LOGS=True), \
         patch.object(SnifferPersistence, '_run_retention_cleanup', return_value=None):
        connection = config.get_conn()
        try:
            yield connection
        finally:
            connection.close()


class AlertIdentityTests(unittest.TestCase):
    def test_identity_requires_occurrence_and_explicit_rule_version(self):
        identity = alert_occurrence_id(EVENT, 'app.test', '1', 0)
        self.assertEqual(valid_alert_event_id(identity), identity)
        for args in ((None, 'app.test', '1', 0), (EVENT, None, '1', 0),
                     (EVENT, 'app.test', '', 0), (EVENT, 'app.test', '1', True),
                     (EVENT, 'app.test', '1', -1), (EVENT, 'app.test', '1', 65536)):
            self.assertIsNone(alert_occurrence_id(*args))
        self.assertIsNone(valid_alert_event_id(identity + '\n'))
        self.assertIsNone(valid_alert_event_id('mem-alert-1'))
        distinct = {
            identity, alert_occurrence_id(EVENT, 'app.test', '1', 1),
            alert_occurrence_id(EVENT, 'app.other', '1', 0),
            alert_occurrence_id(EVENT, 'app.test', '2', 0),
            alert_occurrence_id(EVENT[:-1] + '1', 'app.test', '1', 0),
        }
        self.assertEqual(len(distinct), 5)

    def test_slots_are_assigned_before_coalescing_and_ignore_mutable_context(self):
        first = pipeline([alert(detail='first'), alert(detail='second')]).analyze(packet())
        replay = pipeline([alert('app.other'), alert(score=0.99, detail='changed'), alert(score=0.1)]).analyze(packet())
        self.assertNotEqual(first[0]['alert_event_id'], first[1]['alert_event_id'])
        self.assertEqual([row['alert_event_id'] for row in first],
                         [row['alert_event_id'] for row in replay[1:]])
        # Downstream suppression of one output cannot renumber the surviving slot.
        self.assertEqual(first[1:][0]['alert_event_id'], replay[2]['alert_event_id'])

    def test_unknown_provenance_or_nonjournal_packets_remain_legacy(self):
        unknown = pipeline([{'attack_type': 'Same title'}, {'attack_type': 'Same title'}]).analyze(packet())
        self.assertTrue(all('alert_event_id' not in row for row in unknown))
        legacy = packet()
        legacy.pop('capture_event_id')
        self.assertNotIn('alert_event_id', pipeline([alert()]).analyze(legacy)[0])

    def test_custom_rules_are_scoped_by_source_configuration_and_position(self):
        args = ('rules.custom', 0, 'Same name', '*', 443, 30, 1)
        key = custom_rule_key(*args)
        self.assertEqual(key, custom_rule_key(*args))
        self.assertNotEqual(key, custom_rule_key('signature.custom', *args[1:]))
        self.assertNotEqual(key, custom_rule_key(args[0], 1, *args[2:]))
        self.assertNotEqual(key, custom_rule_key(*args[:-1], 2))
        with tempfile.TemporaryDirectory() as folder:
            rules = RuleEngine(str(Path(folder)/'rules.json'))
            rules.rules = [{'name': 'Same name', 'dport': 443, 'count_threshold': 1}]
            raw = rules.analyze(packet())
            self.assertEqual(raw['detection_rule_key'], key)
            signature = SignatureIDS()
            signature.custom_rules = rules.rules
            sig_raw = signature.analyze_packet({**packet(), 'tcp_flags': 'A'})
            self.assertEqual(sig_raw['detection_rule_key'], custom_rule_key('signature.custom', *args[1:]))
            signature.flood_threshold = 1
            flood = signature.analyze_packet(packet())
            self.assertEqual(flood['detection_rule_key'], 'signature.generic_flood')

    def test_reopened_history_keeps_first_alert_and_distinguishes_new_events(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'history.db'
            for replay in (False, True):
                with history(path) as connection:
                    persistence = SnifferPersistence()
                    try:
                        alerts = pipeline([alert(detail='changed' if replay else 'Cookie: private-value')]).analyze(packet())
                        ticket = persistence.persist_batch_tracked([(packet(), alerts)])
                        self.assertTrue(ticket.wait(3).succeeded)
                        self.assertEqual(connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0], 1)
                        self.assertEqual(connection.execute('SELECT detection_rule_key,detection_rule_version FROM alerts').fetchone(),
                                         ('app.test', '1'))
                        if replay:
                            self.assertEqual(persistence.stats()['persisted_alerts'], 0)
                            detail = connection.execute('SELECT detail FROM alerts').fetchone()[0]
                            self.assertNotIn('private-value', detail)
                            self.assertNotEqual(detail, 'changed')
                            for row, raw in ((packet(EVENT[:-1] + '1'), alert()),
                                             (packet(), alert('app.other')),
                                             (packet(), alert(version='2'))):
                                self.assertTrue(persistence.persist_batch_tracked([
                                    (row, pipeline([raw]).analyze(row))]).wait(3).succeeded)
                            self.assertEqual(connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0], 4)
                    finally:
                        persistence.close()

    def test_migration_preserves_legacy_duplicates_and_invalid_keys_do_not_collapse(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'history.db'
            connection = sqlite3.connect(path)
            columns = [column for column in storage._ALERT_COLUMNS if column not in
                       {'alert_event_id', 'detection_rule_key', 'detection_rule_version'}]
            connection.execute('CREATE TABLE alerts (id INTEGER PRIMARY KEY,' + ','.join(f'{column} TEXT' for column in columns) + ')')
            connection.executemany('INSERT INTO alerts(attack_type) VALUES (?)', [('Same title',)] * 2)
            connection.commit()
            connection.close()
            with history(path) as connection:
                self.assertEqual(connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0], 2)
                result = storage.insert_batch([], [{'alert_event_id': 'invalid', 'attack_type': 'Same title'}] * 2)
                self.assertEqual(result['alerts_inserted'], 2)
                self.assertEqual(connection.execute('SELECT COUNT(alert_event_id) FROM alerts').fetchone()[0], 0)

    def test_unrelated_alert_constraint_still_rolls_back_packet_transaction(self):
        with tempfile.TemporaryDirectory() as folder, history(Path(folder)/'history.db') as connection:
            connection.execute('CREATE UNIQUE INDEX test_title ON alerts(attack_type)')
            storage.insert_batch([], [{'attack_type': 'Same title'}])
            with self.assertRaises(sqlite3.IntegrityError):
                storage.insert_batch([{'capture_event_id': EVENT}], [{
                    'alert_event_id': alert_occurrence_id(EVENT, 'app.test', '1', 0), 'attack_type': 'Same title'}])
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM packets').fetchone()[0], 0)

    @unittest.skipUnless(os.name == 'nt', 'DPAPI journal requires Windows')
    def test_journal_reopen_before_ack_replays_packet_and_alert_without_new_rows(self):
        with tempfile.TemporaryDirectory() as folder:
            journal_path, history_path = Path(folder)/'capture.db', Path(folder)/'history.db'
            for replay in (False, True):
                journal = CaptureJournal(journal_path)
                try:
                    if not replay:
                        journal.append([packet()])
                    identifier, rows = journal.first()
                    with history(history_path) as connection:
                        persistence = SnifferPersistence()
                        try:
                            alerts = pipeline([alert()]).analyze(rows[0])
                            self.assertTrue(persistence.persist_batch_tracked([(rows[0], alerts)]).wait(3).succeeded)
                            self.assertEqual(connection.execute('SELECT COUNT(*) FROM packets').fetchone()[0], 1)
                            self.assertEqual(connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0], 1)
                        finally:
                            persistence.close()
                    if replay:
                        journal.acknowledge(identifier)
                finally:
                    journal.close()
