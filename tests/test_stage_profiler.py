import unittest
from types import SimpleNamespace
from unittest.mock import patch
from backend.app.services.stage_profiler import StageProfiler


class StageProfilerTests(unittest.TestCase):
    def test_preserves_results_and_errors_without_recording_payload(self):
        owner = SimpleNamespace(run=lambda value: value)
        profiler = StageProfiler(sample_every=1)
        profiler.wrap(owner, 'run', 'stage')
        self.assertEqual(owner.run('private-secret'), 'private-secret')
        self.assertNotIn('private-secret', str(profiler.stats()))
        self.assertEqual(profiler.stats()['stages']['stage']['samples'], 1)
        owner.fail = lambda: (_ for _ in ()).throw(ValueError('private-error'))
        profiler.wrap(owner, 'fail', 'failure')
        with self.assertRaises(ValueError):
            owner.fail()
        self.assertEqual(profiler.stats()['stages']['failure']['samples'], 1)
        self.assertNotIn('private-error', str(profiler.stats()))

    def test_sampling_interval_and_expiry(self):
        owner = SimpleNamespace(run=lambda: None)
        profiler = StageProfiler(sample_every=2)
        profiler.wrap(owner, 'run', 'stage')
        with patch('backend.app.services.stage_profiler.time.monotonic', return_value=100):
            for _ in range(5):
                owner.run()
            self.assertEqual(profiler.stats()['stages']['stage']['samples'], 2)
        with patch('backend.app.services.stage_profiler.time.monotonic', return_value=161):
            stats = profiler.stats()['stages']['stage']
            self.assertEqual(stats['samples'], 0)
            self.assertEqual(stats['seen_calls'], 5)
