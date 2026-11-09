import unittest
from unittest.mock import Mock, patch

from benchmarks.long_soak_runner import LongSoakSampler, available_cpu_count, classify_profile_result, summarize_resource_samples


class CpuBudgetTests(unittest.TestCase):
    def result(self, cpu=144, cpus=2):
        return {"resource_profile": {"cpu_avg_percent": cpu, "cpu_peak_percent": cpu,
                "available_cpu_count": cpus, "memory_growth_mb": 0, "memory_stabilized": True},
                "general": {"events_failed_total": 0}, "ops_health": {"pressure_reasons": []}}

    def classify(self, result, **kwargs):
        return classify_profile_result(result, max_cpu_avg_percent=100, max_cpu_peak_percent=200,
                                       max_memory_growth_mb=150, fail_on_unbounded_growth=True, **kwargs)

    def test_multicore_units_are_explicit_without_changing_raw_measurements(self):
        result = self.result()
        normalized = self.classify(result, cpu_budget_basis="available-cpus")
        self.assertTrue(normalized["passed"])
        self.assertEqual(normalized["cpu_budget_average_percent"], 72)
        self.assertEqual(result["resource_profile"]["cpu_avg_percent"], 144)
        self.assertFalse(self.classify(result)["passed"])

    def test_cpu_and_pipeline_failures_are_not_suppressed(self):
        self.assertFalse(self.classify(self.result(202), cpu_budget_basis="available-cpus")["passed"])
        result = self.result(50)
        result["general"]["events_failed_total"] = 1
        self.assertIn("pipeline_failures_detected", self.classify(result, cpu_budget_basis="available-cpus")["failures"])

    def test_affinity_is_preferred_and_unknown_capacity_falls_back_conservatively(self):
        self.assertEqual(available_cpu_count(Mock(cpu_affinity=lambda: [2, 3])), 2)
        with patch("benchmarks.long_soak_runner.psutil.cpu_count", return_value=None):
            self.assertEqual(available_cpu_count(object()), 1)

    def test_unknown_budget_basis_is_rejected(self):
        with self.assertRaises(ValueError):
            self.classify(self.result(), cpu_budget_basis="unknown")

    def test_short_intervals_are_not_fabricated_cpu_measurements(self):
        sampler = LongSoakSampler()
        sampler._process = Mock()
        sampler._process.memory_info.return_value.rss = 1024 * 1024
        sampler._process.cpu_percent.return_value = 144
        sampler._last_cpu_at = 10
        sampler._started_at = 10
        with patch("benchmarks.long_soak_runner.time.perf_counter", return_value=10.01):
            sampler._append_sample()
        self.assertIsNone(sampler.samples()[0]["cpu_percent"])
        sampler._process.cpu_percent.assert_not_called()
        with patch("benchmarks.long_soak_runner.time.perf_counter", return_value=10.25):
            sampler._append_sample()
        summary = summarize_resource_samples(sampler.samples())
        self.assertEqual(summary["cpu_sample_count"], 1)
        self.assertEqual(summary["cpu_avg_percent"], 144)
        result = self.result()
        result["resource_profile"]["cpu_sample_count"] = 0
        self.assertIn("cpu_samples_unavailable", self.classify(result)["failures"])
