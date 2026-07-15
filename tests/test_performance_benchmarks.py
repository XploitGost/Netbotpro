import json
import tempfile
import time
import unittest
from pathlib import Path

from benchmarks.benchmark_batch_persistence import run_persistence_benchmark
from benchmarks.benchmark_live_ring_buffer import run_live_ring_benchmark
from benchmarks.benchmark_packet_pipeline import run_packet_queue_benchmark
from benchmarks.benchmark_report import (
    BenchmarkConfig,
    ResourceSampler,
    synthetic_alert,
    synthetic_packet,
    write_reports,
)
from benchmarks.benchmark_websocket_aggregator import (
    run_event_aggregator_benchmark,
)
from benchmarks.benchmark_worker_pool import run_worker_pool_benchmark
from benchmarks.soak_test_pipeline import run_soak_test


class PerformanceBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.config = BenchmarkConfig(
            duration_sec=0.05,
            events_per_sec=100,
            flows=4,
            packet_rate=90,
            alert_rate=10,
            ci_safe=True,
        )

    def test_synthetic_generators_are_safe_and_deterministic(self):
        packet = synthetic_packet(7, 4)
        alert = synthetic_alert(7, packet)

        self.assertEqual(packet, synthetic_packet(7, 4))
        self.assertEqual(packet["source"], "synthetic_benchmark")
        self.assertEqual(alert["flow_id"], packet["flow_key"])
        serialized = json.dumps({"packet": packet, "alert": alert}).lower()
        for forbidden in ["authorization", "cookie", "password", "bearer "]:
            self.assertNotIn(forbidden, serialized)

    def test_resource_sampler_produces_structural_metrics(self):
        sampler = ResourceSampler(interval_sec=0.01)
        sampler.start()
        time.sleep(0.03)
        metrics = sampler.stop()

        self.assertGreater(metrics["memory_peak_bytes"], 0)
        self.assertIn("cpu_percent_avg", metrics)
        self.assertIn("memory_growth_bytes", metrics)

    def test_stage_benchmarks_produce_bounded_metrics(self):
        scenarios = {
            "packet_queue": run_packet_queue_benchmark,
            "flow_worker_pool": run_worker_pool_benchmark,
            "event_aggregator": run_event_aggregator_benchmark,
            "persistence": run_persistence_benchmark,
            "live_ring_buffer": run_live_ring_benchmark,
        }

        for name, scenario in scenarios.items():
            with self.subTest(stage=name):
                metrics = scenario(self.config)
                self.assertTrue(metrics["bounded"])
                self.assertIn("health", metrics)

    def test_ci_safe_soak_is_local_bounded_and_complete(self):
        started = time.perf_counter()
        results = run_soak_test(self.config)
        elapsed = time.perf_counter() - started

        self.assertGreater(results["general"]["events_processed_total"], 0)
        self.assertGreaterEqual(results["general"]["duration_sec"], 0.04)
        self.assertLess(results["general"]["duration_sec"], 1.0)
        self.assertLess(elapsed, 2.0)
        for section in [
            "packet_queue",
            "flow_worker_pool",
            "event_aggregator",
            "websocket",
            "persistence",
            "live_ring_buffer",
            "ops_health",
        ]:
            self.assertIn(section, results)
        for key in [
            "packet_queue_bounded",
            "flow_worker_pool_bounded",
            "persistence_bounded",
            "live_ring_buffer_bounded",
            "reports_redacted",
        ]:
            self.assertTrue(results["validation"][key])
        self.assertFalse(results["validation"]["external_network_used"])
        self.assertFalse(results["validation"]["admin_privileges_required"])
        self.assertFalse(results["validation"]["live_capture_used"])

    def test_report_generator_writes_redacted_json_and_markdown(self):
        results = run_soak_test(self.config)
        results["validation"]["unsafe_fixture"] = {
            "Authorization": "Bearer benchmark-secret-token",
            "password": "benchmark-password",
        }

        with tempfile.TemporaryDirectory() as temporary_directory:
            paths = write_reports(results, temporary_directory)
            json_path = Path(paths["json"])
            markdown_path = Path(paths["markdown"])
            combined = json_path.read_text(encoding="utf-8") + markdown_path.read_text(
                encoding="utf-8"
            )

        self.assertTrue(json_path.name.endswith(".json"))
        self.assertTrue(markdown_path.name.endswith(".md"))
        self.assertNotIn("benchmark-secret-token", combined)
        self.assertNotIn("benchmark-password", combined)
        self.assertIn("[REDACTED]", combined)
        self.assertIn("packet_queue", combined)
        self.assertIn("NetBotPro Synthetic Performance Summary", combined)

    def test_benchmark_sources_do_not_use_capture_or_network_clients(self):
        root = Path(__file__).resolve().parents[1] / "benchmarks"
        source = "\n".join(
            path.read_text(encoding="utf-8") for path in root.glob("*.py")
        ).lower()
        for forbidden in [
            "import socket",
            "import requests",
            "from scapy",
            "systemcapture",
            "subprocess",
        ]:
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
