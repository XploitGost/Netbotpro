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
from benchmarks.load_profiles import get_profile, profile_names
from benchmarks.long_soak_runner import (
    build_parser,
    classify_profile_result,
    generate_tuning_recommendations,
    run_long_soak,
    simulate_websocket_clients,
    summarize_resource_samples,
    write_timeseries_csv,
)
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

    def test_load_profiles_parse_and_ci_safe_caps_long_runs(self):
        self.assertIn("light_desktop", profile_names())
        heavy = get_profile("heavy_desktop")
        capped = heavy.with_overrides(ci_safe=True)

        self.assertEqual(heavy.duration_sec, 30 * 60)
        self.assertLessEqual(capped.duration_sec, 10)
        self.assertLessEqual(capped.events_per_sec, 200)
        self.assertLessEqual(capped.websocket_clients, 2)

    def test_memory_growth_classification_detects_stable_and_leaky_shapes(self):
        stable = summarize_resource_samples(
            [
                {"elapsed_sec": 0, "memory_mb": 100.0, "cpu_percent": 5.0},
                {"elapsed_sec": 30, "memory_mb": 104.0, "cpu_percent": 8.0},
                {"elapsed_sec": 60, "memory_mb": 104.5, "cpu_percent": 7.0},
            ]
        )
        leaky = summarize_resource_samples(
            [
                {"elapsed_sec": 0, "memory_mb": 100.0, "cpu_percent": 10.0},
                {"elapsed_sec": 30, "memory_mb": 190.0, "cpu_percent": 15.0},
                {"elapsed_sec": 60, "memory_mb": 260.0, "cpu_percent": 12.0},
            ]
        )

        self.assertTrue(stable["memory_stabilized"])
        self.assertFalse(stable["possible_memory_leak"])
        self.assertFalse(leaky["memory_stabilized"])
        self.assertTrue(leaky["possible_memory_leak"])
        self.assertIn("possible_continuous_memory_growth", leaky["memory_pressure_reasons"])

    def test_cpu_pressure_classification_and_tuning_hint(self):
        metrics = summarize_resource_samples(
            [
                {"elapsed_sec": 0, "memory_mb": 100.0, "cpu_percent": 85.0},
                {"elapsed_sec": 1, "memory_mb": 101.0, "cpu_percent": 92.0},
                {"elapsed_sec": 2, "memory_mb": 101.0, "cpu_percent": 98.0},
            ]
        )

        self.assertTrue(metrics["sustained_cpu_pressure"])
        self.assertIn("cpu_average_high", metrics["cpu_pressure_reasons"])
        self.assertIn("stronger CPU", metrics["tuning_hint"])

    def test_tuning_recommendations_are_safe_and_specific(self):
        results = {
            "packet_queue": {"dropped_total": 1},
            "flow_worker_pool": {"utilization_percent": 75},
            "websocket": {"events_dropped_total": 1, "events_coalesced_total": 1},
            "persistence": {"events_dropped_total": 1, "backlog_age_ms": 10},
            "live_ring_buffer": {"records_evicted_total": 2},
            "resource_profile": {"sustained_cpu_pressure": False},
            "incident_correlation": {"spam_risk": True},
            "service_attribution": {"errors_total": 1},
        }
        recommendations = "\n".join(generate_tuning_recommendations(results)).lower()

        self.assertIn("netbot_packet_queue_max_size", recommendations)
        self.assertIn("netbot_flow_worker_count", recommendations)
        self.assertIn("websocket pressure", recommendations)
        for unsafe in ["tls decryption", "credential", "mitm", "bypass"]:
            self.assertNotIn(unsafe, recommendations)

    def test_websocket_client_simulation_metrics_are_bounded(self):
        metrics = simulate_websocket_clients(
            client_count=5,
            events_per_sec=100,
            duration_sec=0.05,
            ci_safe=True,
        )

        self.assertEqual(metrics["client_count"], 5)
        self.assertGreater(metrics["slow_clients"], 0)
        self.assertTrue(metrics["client_queues_bounded"])
        self.assertIn("health", metrics)

    def test_long_soak_ci_safe_report_is_redacted_and_complete(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            parser = build_parser()
            args = parser.parse_args(
                [
                    "--profile",
                    "light_desktop",
                    "--duration-sec",
                    "1",
                    "--events-per-sec",
                    "50",
                    "--flows",
                    "5",
                    "--websocket-clients",
                    "2",
                    "--sample-interval-sec",
                    "0.05",
                    "--ci-safe",
                    "--output",
                    temporary_directory,
                    "--pcap",
                    str(Path(temporary_directory) / "authorized-test.pcap"),
                    "--pcap-loop",
                ]
            )
            results = run_long_soak(args)
            csv_path = write_timeseries_csv(
                results["resource_samples"], temporary_directory
            )
            combined = json.dumps(results).lower()

        self.assertTrue(results["safe_synthetic_only"])
        self.assertEqual(results["load_profile"]["name"], "light_desktop")
        self.assertIn("resource_profile", results)
        self.assertIn("tuning_recommendations", results)
        self.assertIn("pcap_replay", results)
        self.assertTrue(results["pcap_replay"]["enabled"])
        self.assertFalse(results["validation"]["external_network_used"])
        self.assertFalse(results["validation"]["live_capture_used"])
        self.assertTrue(Path(csv_path).name.endswith(".csv"))
        for secret in ["authorization", "cookie", "password", "bearer "]:
            self.assertNotIn(secret, combined)

    def test_profile_result_flags_threshold_failures(self):
        result = {
            "resource_profile": {
                "memory_growth_mb": 200.0,
                "memory_stabilized": False,
                "cpu_avg_percent": 95.0,
                "cpu_peak_percent": 101.0,
            },
            "general": {"events_failed_total": 1},
            "ops_health": {"pressure_reasons": []},
        }

        validation = classify_profile_result(
            result,
            max_memory_growth_mb=150.0,
            max_cpu_avg_percent=90.0,
            max_cpu_peak_percent=100.0,
            fail_on_unbounded_growth=True,
        )

        self.assertFalse(validation["passed"])
        self.assertIn("memory_growth_threshold_exceeded", validation["failures"])
        self.assertIn("cpu_average_threshold_exceeded", validation["failures"])


if __name__ == "__main__":
    unittest.main()
