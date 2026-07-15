import os
import threading
import time
import unittest
from unittest.mock import patch

from backend.app.services.flow_worker_pool import FlowDispatchKey, FlowWorkerPool


def packet(index: int, *, src: str = "10.0.0.1", dst: str = "8.8.8.8"):
    return {
        "id": f"packet-{index}",
        "sequence": index,
        "src": src,
        "dst": dst,
        "sport": 50000,
        "dport": 443,
        "proto": "TCP",
    }


class FlowWorkerPoolTests(unittest.TestCase):
    def test_creates_configured_workers_and_accepts_jobs(self):
        processed = []
        pool = FlowWorkerPool(processed.append, worker_count=3, queue_max=30)
        try:
            self.assertTrue(pool.submit(packet(1)))
            self.assertTrue(pool.wait_until_drained(1.0))
            stats = pool.stats()
        finally:
            pool.close()

        self.assertEqual(stats["worker_count"], 3)
        self.assertEqual(stats["active_workers"], 3)
        self.assertEqual(stats["jobs_received_total"], 1)
        self.assertEqual(stats["jobs_processed_total"], 1)
        self.assertEqual(processed[0]["sequence"], 1)

    def test_bidirectional_flow_key_and_worker_assignment_are_stable(self):
        forward = packet(1)
        reverse = {
            **forward,
            "src": forward["dst"],
            "dst": forward["src"],
            "sport": forward["dport"],
            "dport": forward["sport"],
        }
        pool = FlowWorkerPool(lambda _packet: None, worker_count=4, queue_max=40)
        try:
            self.assertEqual(
                FlowDispatchKey.from_packet(forward),
                FlowDispatchKey.from_packet(reverse),
            )
            self.assertEqual(
                pool.worker_index_for(forward), pool.worker_index_for(reverse)
            )
        finally:
            pool.close()

    def test_same_flow_preserves_processing_order(self):
        processed = []
        pool = FlowWorkerPool(
            lambda item: processed.append(item["sequence"]),
            worker_count=4,
            queue_max=200,
        )
        try:
            for index in range(30):
                self.assertTrue(pool.submit(packet(index)))
            self.assertTrue(pool.wait_until_drained(2.0))
        finally:
            pool.close()

        self.assertEqual(processed, list(range(30)))

    def test_different_flows_can_process_concurrently(self):
        started = set()
        both_started = threading.Event()
        release = threading.Event()
        lock = threading.Lock()

        def processor(item):
            with lock:
                started.add(item["src"])
                if len(started) == 2:
                    both_started.set()
            release.wait(1.0)

        pool = FlowWorkerPool(processor, worker_count=2, queue_max=20)
        first = packet(1, src="10.0.0.1")
        second = packet(2, src="10.0.0.2")
        while pool.worker_index_for(second) == pool.worker_index_for(first):
            suffix = int(second["src"].rsplit(".", 1)[1]) + 1
            second = packet(2, src=f"10.0.0.{suffix}")
        try:
            pool.submit(first)
            pool.submit(second)
            self.assertTrue(both_started.wait(1.0))
        finally:
            release.set()
            pool.close()

    def test_unknown_packet_uses_safe_fallback_lane(self):
        pool = FlowWorkerPool(lambda _packet: None, worker_count=2, queue_max=10)
        try:
            self.assertTrue(pool.submit({"token": "never-expose-this"}))
            self.assertTrue(pool.wait_until_drained(1.0))
            stats = pool.stats()
        finally:
            pool.close()

        self.assertEqual(stats["unknown_flow_key_total"], 1)
        self.assertNotIn("never-expose-this", str(stats))

    def test_drop_oldest_keeps_newest_queued_job(self):
        processed, pool, release = self._blocked_pool("drop_oldest")
        try:
            self.assertTrue(pool.submit(packet(2)))
            self.assertTrue(pool.submit(packet(3)))
            stats = pool.stats()
            self.assertEqual(stats["queue_depth_total"], 1)
            self.assertEqual(stats["jobs_dropped_total"], 1)
            self.assertEqual(
                stats["last_drop_reason"], "flow_worker_queue_full_drop_oldest"
            )
        finally:
            release.set()
            pool.close()
        self.assertEqual(processed, [1, 3])

    def test_drop_newest_rejects_latest_queued_job(self):
        processed, pool, release = self._blocked_pool("drop_newest")
        try:
            self.assertTrue(pool.submit(packet(2)))
            self.assertFalse(pool.submit(packet(3)))
            stats = pool.stats()
            self.assertEqual(stats["jobs_dropped_total"], 1)
        finally:
            release.set()
            pool.close()
        self.assertEqual(processed, [1, 2])

    def test_reject_new_records_rejection_without_growing_queue(self):
        processed, pool, release = self._blocked_pool("reject_new")
        try:
            self.assertTrue(pool.submit(packet(2)))
            self.assertFalse(pool.submit(packet(3)))
            stats = pool.stats()
            self.assertEqual(stats["queue_depth_total"], 1)
            self.assertEqual(stats["jobs_rejected_total"], 1)
            self.assertEqual(stats["jobs_dropped_total"], 0)
        finally:
            release.set()
            pool.close()
        self.assertEqual(processed, [1, 2])

    def test_block_short_returns_without_blocking_indefinitely(self):
        _processed, pool, release = self._blocked_pool("block_short")
        try:
            self.assertTrue(pool.submit(packet(2)))
            started = time.perf_counter()
            self.assertFalse(pool.submit(packet(3)))
            elapsed = time.perf_counter() - started
            self.assertLess(elapsed, 0.25)
            self.assertEqual(pool.stats()["jobs_rejected_total"], 1)
        finally:
            release.set()
            pool.close()

    def test_failures_and_slow_jobs_are_counted_without_logging_secrets(self):
        def processor(item):
            if item["sequence"] == 1:
                raise RuntimeError("Authorization: Bearer raw-secret")
            time.sleep(0.02)

        pool = FlowWorkerPool(
            processor,
            worker_count=1,
            queue_max=10,
            error_threshold=1,
            slow_job_ms=5,
        )
        try:
            with self.assertLogs(
                "backend.app.services.flow_worker_pool", level="ERROR"
            ) as logs:
                pool.submit(packet(1))
                pool.submit(packet(2))
                self.assertTrue(pool.wait_until_drained(1.0))
            stats = pool.stats()
        finally:
            pool.close()

        self.assertEqual(stats["jobs_failed_total"], 1)
        self.assertEqual(stats["slow_jobs_total"], 1)
        self.assertEqual(stats["health"], "critical")
        self.assertEqual(stats["last_error"], "RuntimeError")
        self.assertNotIn("raw-secret", str(stats))
        self.assertNotIn("raw-secret", "\n".join(logs.output))

    def test_backlog_degrades_health_and_queue_never_exceeds_max(self):
        started = threading.Event()
        release = threading.Event()

        def processor(_item):
            started.set()
            release.wait(1.0)

        pool = FlowWorkerPool(processor, worker_count=1, queue_max=10)
        try:
            pool.submit(packet(0))
            self.assertTrue(started.wait(1.0))
            for index in range(1, 7):
                pool.submit(packet(index))
            stats = pool.stats()
            self.assertLessEqual(stats["queue_depth_total"], 10)
            self.assertEqual(stats["health"], "degraded")
            self.assertIn("flow_worker_queue_backlog", stats["pressure_reasons"])
        finally:
            release.set()
            pool.close()

    def test_disabled_pool_processes_inline_as_legacy_fallback(self):
        processed = []
        pool = FlowWorkerPool(processed.append, enabled=False, worker_count=4)
        try:
            self.assertTrue(pool.submit(packet(1)))
            stats = pool.stats()
        finally:
            pool.close()

        self.assertEqual(processed[0]["sequence"], 1)
        self.assertFalse(stats["enabled"])
        self.assertEqual(stats["active_workers"], 0)
        self.assertEqual(stats["jobs_processed_total"], 1)

    def test_invalid_environment_values_use_safe_defaults(self):
        env = {
            "NETBOT_FLOW_WORKERS_ENABLED": "invalid",
            "NETBOT_FLOW_WORKER_COUNT": "many",
            "NETBOT_FLOW_WORKER_QUEUE_MAX": "none",
            "NETBOT_FLOW_WORKER_OVERFLOW_POLICY": "unsafe",
        }
        with patch.dict(os.environ, env, clear=False):
            pool = FlowWorkerPool.from_env(lambda _packet: None)
        try:
            stats = pool.stats()
        finally:
            pool.close()

        self.assertTrue(stats["enabled"])
        self.assertEqual(stats["worker_count"], 4)
        self.assertEqual(stats["queue_max_total"], 2000)
        self.assertEqual(stats["overflow_policy"], "drop_oldest")

    @staticmethod
    def _blocked_pool(policy):
        started = threading.Event()
        release = threading.Event()
        processed = []

        def processor(item):
            processed.append(item["sequence"])
            if item["sequence"] == 1:
                started.set()
                release.wait(1.0)

        pool = FlowWorkerPool(
            processor,
            worker_count=1,
            queue_max=1,
            overflow_policy=policy,
            block_timeout_sec=0.02,
        )
        pool.submit(packet(1))
        if not started.wait(1.0):
            release.set()
            pool.close()
            raise AssertionError("worker did not start")
        return processed, pool, release


if __name__ == "__main__":
    unittest.main()
