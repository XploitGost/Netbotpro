from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from backend.app.services.event_bus import EventBus
from backend.app.services.journal_history_delivery import JournalHistoryDelivery
from backend.app.services.packet_delivery import AnalyzedPacket
from backend.app.services.persistence_ticket import PersistenceTicket
from backend.app.services.sniffer_persistence import SnifferPersistence
from backend.app.services.sniffer_service import SnifferService, CaptureStartUnavailableError
from core.alert_identity import alert_occurrence_id
from core.capture.batch_delivery import BatchCompletionReceipt, BatchDeliveryError, JournalBatchDelivery
from core.capture.journal import CaptureJournal
from core.capture.process_session import ProcessCaptureSession
from core.netbotpro_logging import config


EVENT = 'cap-v1:' + 'a' * 32 + ':1:0'


def analyzed(meta):
    packet = dict(meta)
    packet['id'] = packet['capture_event_id']
    alerts = [{'alert_event_id': alert_occurrence_id(packet['id'], 'app.test', '1', 0),
               'detection_rule_key': 'app.test', 'detection_rule_version': '1',
               'packet_id': packet['id'], 'attack_type': 'Fixture detection'}]
    return AnalyzedPacket(packet, None, 'fixture-flow', alerts, [], [])


def row(offset=0):
    return {'capture_event_id': EVENT[:-1] + str(offset), 'sequence': offset,
            'src': '192.0.2.1', 'dst': '198.51.100.1', 'proto': 'TCP'}


@contextmanager
def history(path):
    with patch.multiple(config, DB_PATH=str(path), _CONN=None, PERSIST_LOGS=True), \
         patch.object(SnifferPersistence, '_run_retention_cleanup', return_value=None):
        connection = config.get_conn()
        persistence = SnifferPersistence(max_retries=0)
        try:
            yield connection, persistence
        finally:
            persistence.close()
            connection.close()


class FakeCapture:
    def __init__(self, callback):
        self.callback = callback
        self.running = False
    def start(self, iface=None):
        self.iface = iface
        self.running = True
        for index in range(40):
            self.callback({'sequence': index, 'src': '192.0.2.1', 'tls_alpn': ['h2']})
    def stop(self):
        self.running = False
    def selected_iface(self):
        return self.iface
    def capture_status(self):
        return {'running': self.running}


class JournalHistoryDeliveryTests(unittest.TestCase):
    def test_commit_publish_and_ack_order_with_one_submission_for_a_batch(self):
        events, acknowledged = [], []
        def submit(records):
            events.append(('commit', len(records)))
            ticket = PersistenceTicket(sum(1 + len(alerts) for _, alerts in records))
            ticket._resolve('committed')
            return ticket
        bridge = JournalHistoryDelivery(analyzed, submit,
            lambda result: events.append(('publish', result.packet['sequence'])))
        delivery = JournalBatchDelivery(bridge.analyze,
            lambda identifier: (acknowledged.append(identifier), events.append(('ack', identifier))),
            prepare=bridge.validate_batch, on_completed=lambda: None, complete_batch=bridge.complete)
        delivery.deliver(4, [row(), row(1)])
        self.assertEqual(events, [('commit', 2), ('publish', 0), ('publish', 1), ('ack', 4)])
        self.assertEqual(acknowledged, [4])

    def test_all_unconfirmed_receipts_retain_batch_without_publication(self):
        for status in ('pending', 'failed', 'skipped', 'dropped', 'rejected', 'unconfirmed', 'unavailable'):
            with self.subTest(status=status):
                ticket = PersistenceTicket(2)
                if status != 'pending':
                    ticket._resolve(status)
                publish, ack = Mock(), Mock()
                bridge = JournalHistoryDelivery(analyzed, lambda records: ticket, publish, timeout_sec=0.001)
                delivery = JournalBatchDelivery(bridge.analyze, ack, prepare=bridge.validate_batch,
                    on_completed=lambda: None, complete_batch=bridge.complete)
                with self.assertRaises(BatchDeliveryError) as raised:
                    delivery.deliver(1, [row()])
                self.assertEqual(raised.exception.stage, 'completion')
                publish.assert_not_called()
                ack.assert_not_called()

    def test_invalid_identities_and_oversized_groups_fail_before_submission(self):
        submit = Mock()
        bridge = JournalHistoryDelivery(analyzed, submit, Mock())
        for packets in ([], [row()] * 2, [{'capture_event_id': 'mem-pkt-1'}], [row(n) for n in range(33)]):
            with self.assertRaises(ValueError):
                bridge.validate_batch(packets)
        changed = AnalyzedPacket({'capture_event_id': row(1)['capture_event_id']}, None, '', [], [], [])
        with self.assertRaises(ValueError):
            JournalHistoryDelivery(lambda packet: changed, submit, Mock()).analyze(row())
        bad_alert = AnalyzedPacket(row(), None, '', [{}], [], [])
        with self.assertRaises(ValueError):
            JournalHistoryDelivery(lambda packet: bad_alert, submit, Mock()).analyze(row())
        large = AnalyzedPacket(row(), None, '', [{'alert_event_id': alert_occurrence_id(EVENT, 'app.test', '1', n)}
                                                for n in range(256)], [], [])
        with self.assertRaises(ValueError):
            bridge.complete(1, [large])
        submit.assert_not_called()

    def test_wrong_ticket_count_or_legacy_result_never_publishes(self):
        wrong = PersistenceTicket(1)
        wrong._resolve('committed')
        for ticket in (None, True, {'succeeded': True}, wrong):
            publish = Mock()
            bridge = JournalHistoryDelivery(analyzed, lambda records: ticket, publish)
            with self.assertRaises(RuntimeError):
                bridge.complete(1, [analyzed(row())])
            publish.assert_not_called()
        for timeout in (0, -1, float('nan'), float('inf'), 11, True):
            with self.assertRaises(ValueError):
                JournalHistoryDelivery(analyzed, Mock(), Mock(), timeout_sec=timeout)

    def test_publication_failure_after_commit_is_not_acknowledged(self):
        ticket = PersistenceTicket(2)
        ticket._resolve('committed')
        publish = Mock(side_effect=RuntimeError('private failure'))
        ack = Mock()
        bridge = JournalHistoryDelivery(analyzed, lambda records: ticket, publish)
        delivery = JournalBatchDelivery(bridge.analyze, ack, on_completed=lambda: None,
            complete_batch=bridge.complete)
        with self.assertRaises(BatchDeliveryError) as raised:
            delivery.deliver(1, [row()])
        self.assertEqual(raised.exception.stage, 'completion')
        self.assertNotIn('private failure', str(raised.exception))
        ack.assert_not_called()

    def test_policy_configuration_and_disabled_storage_fail_before_capture(self):
        for mode, journal in (('invalid', '1'), ('history', '0')):
            with patch.dict(os.environ, NETBOT_JOURNAL_ACK_MODE=mode, NETBOT_CAPTURE_JOURNAL=journal):
                with self.assertRaises(ValueError):
                    SnifferService(EventBus())
        service = SnifferService.__new__(SnifferService)
        service._history_delivery = Mock()
        service._persistence = Mock()
        service._persistence.stats.return_value = {'packet_storage_enabled': False}
        with self.assertRaises(CaptureStartUnavailableError):
            service._start_capture_session(None)

    def test_service_wires_strict_completion_but_leaves_default_callback_unchanged(self):
        for strict in (False, True):
            service = SnifferService.__new__(SnifferService)
            service._history_delivery = Mock() if strict else None
            service._persistence = Mock()
            service._persistence.stats.return_value = {'packet_storage_enabled': True}
            service._on_packet = Mock()
            service._detection_pipeline = Mock()
            service.capture_preflight = lambda: {'ready': True}
            service._resolve_local_interface_or_raise = lambda iface: iface
            engine = ProcessCaptureSession(lambda packet: None, journal_path='unused-test-path')
            engine.start = Mock()
            engine.selected_iface = lambda: 'test-interface'
            service._capture_provider = Mock()
            service._capture_provider.create_session.return_value = engine
            service._capture_provider.describe_interface.return_value = 'test-interface'
            service._start_capture_session(None)
            callback = service._history_delivery.analyze if strict else service._on_packet
            service._capture_provider.create_session.assert_called_once_with(callback)
            self.assertEqual(engine._complete_batch, service._history_delivery.complete if strict else None)

    def test_post_commit_publication_does_not_enqueue_history_again(self):
        service = SnifferService.__new__(SnifferService)
        service._state = Mock()
        service._live_ring_buffer = Mock()
        service._append_incident_view = Mock()
        service._submit_flow_view = Mock()
        service._persist_analyzed_flow = Mock()
        service._persistence = Mock()
        service._publisher = Mock()
        item = analyzed(row())
        service._make_packet_delivery(persist_history=False).deliver(item)
        service._persistence.persist.assert_not_called()
        service._state.add_packet.assert_called_once_with(item.packet)
        service._publisher.publish_packet.assert_called_once_with(item.packet)
        service._make_packet_delivery().deliver(item)
        service._persistence.persist.assert_called_once_with(item.packet, item.alerts)

    def test_strict_analysis_failure_is_not_swallowed_if_environment_changes(self):
        service = SnifferService.__new__(SnifferService)
        service._journal_ack_mode = 'history'
        service._apply_payload_policy = Mock()
        service._detection_pipeline = Mock()
        service._detection_pipeline.analyze.side_effect = RuntimeError('fixture detector failure')
        with patch.dict(os.environ, NETBOT_CAPTURE_JOURNAL='0'), \
             patch('backend.app.services.sniffer_service.logger'):
            with self.assertRaisesRegex(RuntimeError, 'fixture detector failure'):
                service._analyze_packet(dict(row(), id=EVENT))

    @unittest.skipUnless(os.name == 'nt', 'DPAPI journal requires Windows')
    def test_process_capture_commits_two_groups_then_acks_all_forty_packets(self):
        with tempfile.TemporaryDirectory() as folder, history(Path(folder)/'history.db') as (connection, persistence):
            published = []
            bridge = JournalHistoryDelivery(analyzed, persistence.persist_batch_tracked,
                lambda result: published.append(result.packet['sequence']))
            session = ProcessCaptureSession(bridge.analyze, factory=FakeCapture,
                journal_path=Path(folder)/'capture.db', prepare_batch=bridge.validate_batch,
                complete_batch=bridge.complete)
            session.start()
            session.stop()
            self.assertEqual(published, list(range(40)))
            status = session.capture_status()
            self.assertTrue(status['journal_completion_required'])
            self.assertEqual(status['journal_acknowledged_records'], 40)
            self.assertEqual(status['journal_pending_records'], 0)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM packets').fetchone()[0], 40)
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0], 40)
            for table in ('packets', 'alerts'):
                self.assertEqual(connection.execute(f'SELECT DISTINCT tls_alpn FROM {table}').fetchall(), [('h2',)])
            self.assertEqual(persistence.stats()['flush_batches'], 2)

    @unittest.skipUnless(os.name == 'nt', 'DPAPI journal requires Windows')
    def test_commit_then_publication_failure_replays_without_duplicate_history(self):
        with tempfile.TemporaryDirectory() as folder:
            path, db = Path(folder)/'capture.db', Path(folder)/'history.db'
            for replay in (False, True):
                journal = CaptureJournal(path)
                try:
                    if not replay:
                        journal.append([row()])
                    identifier, packets = journal.first()
                    with history(db) as (connection, persistence):
                        publish = Mock() if replay else Mock(side_effect=RuntimeError('after commit'))
                        bridge = JournalHistoryDelivery(analyzed, persistence.persist_batch_tracked, publish)
                        delivery = JournalBatchDelivery(bridge.analyze, journal.acknowledge,
                            prepare=bridge.validate_batch, on_completed=lambda: None,
                            complete_batch=bridge.complete)
                        if replay:
                            delivery.deliver(identifier, packets)
                            self.assertIsNone(journal.first())
                            self.assertEqual(persistence.stats()['persisted_alerts'], 0)
                        else:
                            with self.assertRaises(BatchDeliveryError):
                                delivery.deliver(identifier, packets)
                            self.assertIsNotNone(journal.first())
                        self.assertEqual(connection.execute('SELECT COUNT(*) FROM packets').fetchone()[0], 1)
                        self.assertEqual(connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0], 1)
                finally:
                    journal.close()
