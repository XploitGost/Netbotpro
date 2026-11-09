import threading
import time
import unittest

from backend.app.services.batch_persistence import BatchPersistenceWriter, _FlushCommand


def wait_for_barrier(writer):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        with writer._queue.mutex:
            if any(isinstance(item, _FlushCommand) for item in writer._queue.queue):
                return
        time.sleep(0.001)
    raise AssertionError('flush barrier was not queued')


class PersistenceFlushContractTests(unittest.TestCase):
    def test_completed_receipt_is_explicit_and_keeps_historical_failure_visible(self):
        failing = True
        writes = []
        def write(grouped):
            if failing:
                raise OSError('private storage details')
            writes.append(grouped)
        writer = BatchPersistenceWriter(write, retry_max=0,
            batch_sizes={'packet_record': 100}, flush_ms={'packet_record': 60000})
        try:
            writer.enqueue('packet_record', {'id': 1})
            failed = writer.flush_result()
            self.assertEqual(failed.status, 'completed')
            self.assertEqual((failed.failed_before, failed.failed_after), (0, 1))
            self.assertFalse(failed.succeeded)
            self.assertNotIn('private storage details', str(failed))
            failing = False
            writer.enqueue('packet_record', {'id': 2})
            clean = writer.flush_result()
            self.assertEqual(clean.status, 'completed')
            self.assertTrue(clean.succeeded)
            self.assertEqual((clean.failed_before, clean.failed_after), (1, 1))
            self.assertEqual(writes[0]['packet_record'][0]['payload']['id'], 2)
        finally:
            writer.close()

    def test_receipt_waits_for_active_write_and_detects_loss_while_waiting(self):
        entered, release = threading.Event(), threading.Event()
        results = []
        def blocked(grouped):
            entered.set()
            release.wait(5)
        writer = BatchPersistenceWriter(blocked, queue_max=2,
            overflow_policy='drop_oldest', batch_sizes={'packet_record': 1})
        waiter = threading.Thread(target=lambda: results.append(writer.flush_result(3)))
        try:
            writer.enqueue('packet_record', {'id': 1})
            self.assertTrue(entered.wait(3))
            writer.enqueue('packet_record', {'id': 2})
            waiter.start()
            wait_for_barrier(writer)
            self.assertEqual(results, [])
            # Evict packet 2, not the barrier behind it.
            self.assertTrue(writer.enqueue('packet_record', {'id': 3}))
            release.set()
            waiter.join(3)
            self.assertFalse(waiter.is_alive())
            receipt = results[0]
            self.assertEqual(receipt.status, 'completed')
            self.assertEqual((receipt.dropped_before, receipt.dropped_after), (0, 1))
            self.assertFalse(receipt.succeeded)
        finally:
            release.set()
            if waiter.ident is not None:
                waiter.join(5)
            writer.close()

    def test_timeout_does_not_cancel_the_pending_barrier(self):
        entered, release = threading.Event(), threading.Event()
        def blocked(grouped):
            entered.set()
            release.wait(5)
        writer = BatchPersistenceWriter(blocked, batch_sizes={'packet_record': 1})
        try:
            writer.enqueue('packet_record', {'id': 1})
            self.assertTrue(entered.wait(3))
            receipt = writer.flush_result(0.02)
            self.assertEqual(receipt.status, 'timeout')
            self.assertFalse(receipt.succeeded)
            release.set()
            self.assertTrue(writer.flush())
            self.assertEqual(writer.metrics()['events_written_total'], 1)
        finally:
            release.set()
            writer.close()

    def test_queue_admission_timeout_does_not_report_completion(self):
        entered, release = threading.Event(), threading.Event()
        def blocked(grouped):
            entered.set()
            release.wait(5)
        writer = BatchPersistenceWriter(blocked, queue_max=1,
            batch_sizes={'packet_record': 1})
        try:
            writer.enqueue('packet_record', {'id': 1})
            self.assertTrue(entered.wait(3))
            writer.enqueue('packet_record', {'id': 2})
            receipt = writer.flush_result(0.02)
            self.assertEqual(receipt.status, 'queue_timeout')
            self.assertFalse(receipt.succeeded)
        finally:
            release.set()
            writer.close()

    def test_synchronous_and_stopped_worker_results_are_distinct(self):
        synchronous = BatchPersistenceWriter(lambda grouped: None, enabled=False)
        self.assertEqual(synchronous.flush_result().status, 'synchronous')
        self.assertTrue(synchronous.flush())
        writer = BatchPersistenceWriter(lambda grouped: None)
        writer.close()
        receipt = writer.flush_result()
        self.assertEqual(receipt.status, 'worker_unavailable')
        self.assertFalse(receipt.succeeded)

    def test_failed_forced_write_is_not_a_successful_flush(self):
        def fail(grouped):
            raise OSError('private storage details')
        writer = BatchPersistenceWriter(fail, retry_max=0,
            batch_sizes={'packet_record': 100}, flush_ms={'packet_record': 60000})
        try:
            self.assertTrue(writer.enqueue('packet_record', {'id': 1}))
            self.assertFalse(writer.flush())
        finally:
            writer.close()

    def test_evicted_barrier_never_reports_success(self):
        entered, release = threading.Event(), threading.Event()
        result = []
        def blocked(grouped):
            entered.set()
            release.wait(5)
        writer = BatchPersistenceWriter(blocked, queue_max=1,
            overflow_policy='drop_oldest', batch_sizes={'packet_record': 1})
        waiter = threading.Thread(target=lambda: result.append(writer.flush(3)))
        try:
            writer.enqueue('packet_record', {'id': 1})
            self.assertTrue(entered.wait(3))
            waiter.start()
            wait_for_barrier(writer)
            self.assertTrue(writer.enqueue('packet_record', {'id': 2}))
            waiter.join(3)
            self.assertFalse(waiter.is_alive())
            self.assertEqual(result, [False])
        finally:
            release.set()
            if waiter.ident is not None:
                waiter.join(5)
            writer.close()
