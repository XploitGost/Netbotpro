import threading
import time
import unittest

from backend.app.services.batch_persistence import BatchPersistenceWriter


class BatchPersistenceWriterTests(unittest.TestCase):
    def test_manual_flush_groups_and_redacts_events(self):
        writes = []
        writer = BatchPersistenceWriter(
            writes.append,
            queue_max=10,
            batch_sizes={"packet_record": 50},
            flush_ms={"packet_record": 60_000},
        )
        try:
            writer.enqueue(
                "packet_record",
                {"summary": "Authorization: Bearer raw-secret", "token": "raw"},
            )
            self.assertTrue(writer.flush())
        finally:
            writer.close()
        rendered = str(writes)
        self.assertNotIn("raw-secret", rendered)
        self.assertNotIn("'token': 'raw'", rendered)
        self.assertEqual(writes[0]["packet_record"][0]["type"], "packet_record")

    def test_size_based_flush(self):
        writes = []
        writer = BatchPersistenceWriter(
            writes.append,
            batch_sizes={"packet_record": 2},
            flush_ms={"packet_record": 60_000},
        )
        try:
            writer.enqueue("packet_record", {"id": 1})
            writer.enqueue("packet_record", {"id": 2})
            time.sleep(0.1)
        finally:
            writer.close()
        self.assertEqual(len(writes[0]["packet_record"]), 2)

    def test_time_based_flush(self):
        writes = []
        writer = BatchPersistenceWriter(
            writes.append,
            batch_sizes={"flow_record": 100},
            flush_ms={"flow_record": 20},
        )
        try:
            writer.enqueue("flow_record", {"flow_id": "f1"})
            time.sleep(0.1)
        finally:
            writer.close()
        self.assertEqual(writes[0]["flow_record"][0]["payload"]["flow_id"], "f1")

    def test_retry_is_bounded_and_succeeds(self):
        calls = []

        def flaky(grouped):
            calls.append(grouped)
            if len(calls) < 3:
                raise OSError("temporary")

        writer = BatchPersistenceWriter(flaky, retry_max=2, retry_backoff_ms=1)
        try:
            writer.enqueue("alert_record", {"id": 1}, priority="high")
            time.sleep(0.1)
            metrics = writer.metrics()
        finally:
            writer.close()
        self.assertEqual(len(calls), 3)
        self.assertEqual(metrics["retry_total"], 2)
        self.assertEqual(metrics["events_failed_total"], 0)

    def test_final_failure_exposes_only_error_type(self):
        def fail(_grouped):
            raise RuntimeError("Cookie: private-session")

        writer = BatchPersistenceWriter(fail, retry_max=0)
        try:
            writer.enqueue("alert_record", {"id": 1}, priority="critical")
            time.sleep(0.05)
            metrics = writer.metrics()
        finally:
            writer.close()
        self.assertEqual(metrics["last_error"], "RuntimeError")
        self.assertNotIn("private-session", str(metrics))

    def test_drop_newest_and_reject_new_are_visible(self):
        for policy in ("drop_newest", "reject_new"):
            release = threading.Event()

            def blocked(_grouped):
                release.wait(1)

            writer = BatchPersistenceWriter(
                blocked,
                queue_max=1,
                overflow_policy=policy,
                batch_sizes={"packet_record": 1},
            )
            try:
                writer.enqueue("packet_record", {"id": 1})
                time.sleep(0.02)
                writer.enqueue("packet_record", {"id": 2})
                accepted = writer.enqueue("packet_record", {"id": 3})
                metrics = writer.metrics()
                self.assertFalse(accepted)
                self.assertGreaterEqual(metrics["events_dropped_total"], 1)
                self.assertEqual(metrics["last_drop_reason"], f"queue_full_{policy}")
            finally:
                release.set()
                writer.close()

    def test_drop_oldest_keeps_queue_bounded(self):
        release = threading.Event()
        writer = BatchPersistenceWriter(
            lambda _grouped: release.wait(1),
            queue_max=1,
            overflow_policy="drop_oldest",
            batch_sizes={"packet_record": 1},
        )
        try:
            writer.enqueue("packet_record", {"id": 1})
            time.sleep(0.02)
            writer.enqueue("packet_record", {"id": 2})
            self.assertTrue(writer.enqueue("packet_record", {"id": 3}))
            metrics = writer.metrics()
            self.assertLessEqual(metrics["queue_depth"], metrics["queue_max"])
            self.assertGreaterEqual(metrics["events_dropped_total"], 1)
        finally:
            release.set()
            writer.close()

    def test_disabled_batching_uses_synchronous_compatibility_path(self):
        writes = []
        writer = BatchPersistenceWriter(writes.append, enabled=False)
        self.assertTrue(writer.enqueue("ops_snapshot", {"health": "healthy"}))
        metrics = writer.metrics()
        self.assertFalse(metrics["persistence_enabled"])
        self.assertEqual(metrics["events_written_total"], 1)

    def test_clean_shutdown_flushes_pending_records(self):
        writes = []
        writer = BatchPersistenceWriter(
            writes.append,
            batch_sizes={"packet_record": 100},
            flush_ms={"packet_record": 60_000},
        )
        writer.enqueue("packet_record", {"id": 1})
        writer.close()
        self.assertEqual(writes[0]["packet_record"][0]["payload"]["id"], 1)
        self.assertFalse(writer.metrics()["worker_alive"])


if __name__ == "__main__":
    unittest.main()
