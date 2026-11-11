from contextlib import contextmanager
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from backend.app.services.batch_persistence import BatchPersistenceWriter
from backend.app.services.persistence_contracts import PersistenceWriteOutcome
from backend.app.services.persistence_ticket import PersistenceTicket, MAX_TRACKED_GROUP_EVENTS
from backend.app.services.sniffer_persistence import SnifferPersistence
from core.netbotpro_logging import config, storage


def confirmed(grouped):
    return PersistenceWriteOutcome(sum(map(len, grouped.values())),
                                   confirmed_types=frozenset(grouped))


@contextmanager
def history():
    with tempfile.TemporaryDirectory() as folder, patch.multiple(
        config, DB_PATH=str(Path(folder)/'history.db'), _CONN=None, PERSIST_LOGS=True
    ):
        connection = config.get_conn()
        try:
            yield connection
        finally:
            connection.close()


class PersistenceTicketTests(unittest.TestCase):
    def test_receipt_remains_pending_through_retry_until_confirmed_return(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def write(grouped):
            calls.append(grouped)
            if len(calls) == 1:
                raise OSError('temporary')
            entered.set()
            release.wait(5)
            return confirmed(grouped)
        writer = BatchPersistenceWriter(write, retry_max=1, retry_backoff_ms=0)
        try:
            ticket = writer.enqueue_many_tracked([{'type': 'packet_record'}])
            self.assertTrue(entered.wait(3))
            self.assertEqual(ticket.wait().status, 'pending')
            release.set()
            self.assertTrue(ticket.wait(3).succeeded)
            self.assertEqual(len(calls), 2)
            self.assertEqual(writer.metrics()['retry_total'], 1)
        finally:
            release.set()
            writer.close()

    def test_admission_and_timeout_do_not_confirm_commit_or_cancel_work(self):
        entered, release = threading.Event(), threading.Event()
        writes = []
        def blocked(grouped):
            writes.append(grouped)
            entered.set()
            release.wait(5)
            return confirmed(grouped)
        writer = BatchPersistenceWriter(blocked)
        try:
            ticket = writer.enqueue_many_tracked([
                {'type': 'packet_record', 'payload': {'summary': 'Authorization: Bearer raw-secret'}},
                {'type': 'alert_record', 'payload': {'detail': 'Cookie: private-value'}},
            ])
            self.assertTrue(entered.wait(3))
            self.assertEqual(ticket.wait(0.01).status, 'pending')
            self.assertFalse(ticket.wait().succeeded)
            release.set()
            receipt = ticket.wait(3)
            self.assertTrue(receipt.succeeded)
            self.assertEqual(receipt.events, 2)
            self.assertEqual(len(writes), 1)
            self.assertNotIn('raw-secret', str(writes))
            self.assertNotIn('private-value', str(writes))
            self.assertEqual(set(writes[0]['packet_record'][0]),
                             {'type', 'timestamp', 'payload', 'source', 'priority'})
            metrics = writer.metrics()
            self.assertEqual((metrics['events_received_total'], metrics['events_written_total']), (2, 2))
        finally:
            release.set()
            writer.close()

    def test_overflow_resolves_the_specific_ticket_for_all_policies(self):
        for policy in ('drop_oldest', 'drop_newest', 'reject_new'):
            with self.subTest(policy=policy):
                entered, release = threading.Event(), threading.Event()
                def blocked(grouped):
                    entered.set()
                    release.wait(5)
                    return confirmed(grouped)
                writer = BatchPersistenceWriter(blocked, queue_max=1, overflow_policy=policy,
                    batch_sizes={'packet_record': 1})
                try:
                    writer.enqueue('packet_record', {'id': 0})
                    self.assertTrue(entered.wait(3))
                    first = writer.enqueue_many_tracked([{'type': 'packet_record', 'payload': {'id': 1}}])
                    second = writer.enqueue_many_tracked([{'type': 'packet_record', 'payload': {'id': 2}}])
                    if policy == 'drop_oldest':
                        self.assertEqual(first.wait().status, 'dropped')
                        pending = second
                    else:
                        self.assertEqual(second.wait().status, 'rejected')
                        pending = first
                    self.assertEqual(pending.wait().status, 'pending')
                    release.set()
                    self.assertTrue(pending.wait(3).succeeded)
                finally:
                    release.set()
                    writer.close()

    def test_legacy_or_incomplete_confirmation_never_certifies_commit(self):
        for callback in (lambda grouped: None,
                         lambda grouped: {'retries': 0},
                         lambda grouped: PersistenceWriteOutcome(2),
                         lambda grouped: PersistenceWriteOutcome(2, confirmed_types=frozenset({'packet_record'}))):
            writer = BatchPersistenceWriter(callback, enabled=False)
            try:
                ticket = writer.enqueue_many_tracked([{'type': 'packet_record'}, {'type': 'alert_record'}])
                self.assertEqual(ticket.wait().status, 'unconfirmed')
                self.assertTrue(writer.flush())
                self.assertFalse(ticket.wait().succeeded)
            finally:
                writer.close()

    def test_failed_ticket_stays_failed_even_when_later_flush_succeeds(self):
        with history() as connection:
            connection.execute("CREATE TRIGGER reject_alert BEFORE INSERT ON alerts BEGIN SELECT RAISE(ABORT,'private detail'); END")
            connection.commit()
            persistence = SnifferPersistence(max_retries=0)
            try:
                ticket = persistence.persist_batch_tracked([({'id': 'packet-1'}, [{'attack_type': 'test'}])])
                self.assertEqual(ticket.wait(3).status, 'failed')
                self.assertTrue(persistence.flush())
                self.assertEqual(ticket.wait().status, 'failed')
                self.assertEqual(connection.execute('SELECT COUNT(*) FROM packets').fetchone()[0], 0)
                self.assertNotIn('private detail', str(ticket.wait()))
            finally:
                persistence.close()

    def test_real_history_group_commits_packet_and_alert_together(self):
        with history() as connection:
            persistence = SnifferPersistence(batch_size=100, flush_interval=60)
            try:
                ticket = persistence.persist_batch_tracked([
                    ({'id': 'packet-1'}, [{'attack_type': 'test'}]),
                    ({'id': 'packet-2'}, []),
                ])
                self.assertTrue(ticket.wait(3).succeeded)
                self.assertEqual(ticket.wait().events, 3)
                self.assertEqual(connection.execute('SELECT COUNT(*) FROM packets').fetchone()[0], 2)
                self.assertEqual(connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0], 1)
                self.assertEqual(persistence.stats()['events_received_total'], 3)
                self.assertEqual(persistence.stats()['events_written_total'], 3)
            finally:
                persistence.close()

    def test_disabled_history_is_skipped_not_committed(self):
        persistence = SnifferPersistence()
        try:
            with patch.object(storage, 'is_persist_enabled', return_value=False):
                ticket = persistence.persist_batch_tracked([({'id': 'packet-1'}, [])])
                self.assertEqual(ticket.wait(3).status, 'skipped')
            self.assertEqual(persistence.stats()['events_skipped_total'], 1)
        finally:
            persistence.close()

    def test_invalid_bounds_types_and_outcomes_fail_closed(self):
        class Miscounted(list):
            def __len__(self):
                return 1
        writer = BatchPersistenceWriter(lambda grouped: PersistenceWriteOutcome(0, 1,
            confirmed_types=frozenset({'packet_record'})), enabled=False, retry_max=0)
        try:
            for events in ([], [{'type': 'flow_record'}], [{'type': 'packet_record'}] * (MAX_TRACKED_GROUP_EVENTS + 1),
                           Miscounted([{'type': 'packet_record'}, {'type': 'alert_record'}])):
                with self.assertRaises(ValueError):
                    writer.enqueue_many_tracked(events)
            self.assertEqual(writer.enqueue_many_tracked([{'type': 'packet_record'}]).wait().status, 'failed')
        finally:
            writer.close()

    def test_closed_async_writer_is_unavailable_and_terminal_results_do_not_change(self):
        writer = BatchPersistenceWriter(confirmed)
        writer.close()
        ticket = writer.enqueue_many_tracked([{'type': 'packet_record'}])
        self.assertEqual(ticket.wait().status, 'unavailable')
        ticket._resolve('committed')
        self.assertEqual(ticket.wait().status, 'unavailable')
        with self.assertRaises(ValueError):
            PersistenceTicket(0)
