import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from scripts.qa.candidate_soak import MIB, budget_reason, read_reports, run_soak, retire_exited


class CandidateSoakTests(unittest.TestCase):
    def test_completed_helpers_do_not_exhaust_active_process_budget(self):
        dead = Mock()
        dead.is_running.return_value = False
        alive = Mock()
        alive.is_running.return_value = True
        observed = {('dead', 1): dead, ('live', 2): alive}
        cpu = {('dead', 1): 4, ('live', 2): 2}
        retire_exited(observed, cpu)
        self.assertEqual(observed, {('live', 2): alive})
        self.assertEqual(cpu, {('live', 2): 2})

    def test_normal_sample_stays_within_budget(self):
        self.assertIsNone(budget_reason(elapsed=10, duration=900, storage=MIB, rss=MIB, free=4096*MIB, children=5, log_bytes=100))

    def test_each_resource_guard_fails_independently(self):
        base = dict(elapsed=10, duration=900, storage=MIB, rss=MIB, free=4096*MIB, children=5, log_bytes=100)
        for change, expected in [({'elapsed': 1021}, 'deadline'), ({'storage': 513*MIB}, 'storage'),
                                 ({'rss': 2049*MIB}, 'memory'), ({'free': MIB}, 'headroom'),
                                 ({'children': 65}, 'process'), ({'log_bytes': 3*MIB}, 'log')]:
            with self.subTest(expected=expected):
                self.assertIn(expected, budget_reason(**{**base, **change}))

    def test_log_reader_ignores_non_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / 'worker.log'
            log.write_text('not json\n' + json.dumps({'nonce': 'not-a-report'}) + '\n' + json.dumps({'stage': 'capture_sample', 'accepted': 10}))
            self.assertEqual(read_reports(log), [{'stage': 'capture_sample', 'accepted': 10}])

    def test_long_mode_rejects_unbounded_durations_before_launch(self):
        for duration in (0, 120, 1801, 14400, 900.5):
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                run_soak('not-launched', duration)
