import unittest

from scripts.qa.history_perf_smoke import run_perf_smoke


class HistoryPerfSmokeTests(unittest.TestCase):
    def test_perf_smoke_returns_expected_metrics(self):
        result = run_perf_smoke()

        self.assertGreater(result["packets_total"], 1000)
        self.assertGreater(result["alerts_total"], 100)
        self.assertIn("packet_list_ms", result)
        self.assertIn("packet_context_ms", result)
        self.assertIn(result["stream_status"], {"complete", "partial", "fallback"})


if __name__ == "__main__":
    unittest.main()
