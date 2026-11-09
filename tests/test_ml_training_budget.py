import unittest
from unittest.mock import Mock, patch

from core.ids_ml import MLIDS


class TrainingBudgetTests(unittest.TestCase):
    def detector(self):
        clock = Mock(return_value=100.0)
        detector = MLIDS(background_training=True, min_train_size=50,
                         min_retrain_seconds=60, clock=clock)
        detector._buffer.extend([[1.0]*7 for _ in range(50)])
        return detector, clock

    def test_first_training_immediate_but_completed_model_not_retrained_per_burst(self):
        detector, clock = self.detector()
        with patch('core.ids_ml.threading.Thread') as thread:
            detector._train_if_needed()
            self.assertEqual(thread.call_count, 1)
            detector._training_pending = False
            detector._model = object()
            detector._trained = True
            detector._since_last_train = 10000
            for second in (100, 101, 130, 159.999):
                clock.return_value = second
                detector._train_if_needed()
            self.assertEqual(thread.call_count, 1)
            clock.return_value = 160
            detector._train_if_needed()
            self.assertEqual(thread.call_count, 2)
        self.assertEqual(detector.training_stats()['training_attempts'], 2)

    def test_pending_job_does_not_spawn_again_even_after_interval(self):
        detector, clock = self.detector()
        with patch('core.ids_ml.threading.Thread') as thread:
            detector._train_if_needed()
            clock.return_value = 200
            detector._train_if_needed()
            self.assertEqual(thread.call_count, 1)

    def test_reset_allows_fresh_initial_training_and_clears_counters(self):
        detector, clock = self.detector()
        with patch('core.ids_ml.threading.Thread') as thread:
            detector._train_if_needed()
            detector.reset_model()
            self.assertEqual(detector.training_stats()['training_attempts'], 0)
            detector._buffer.extend([[1.0]*7 for _ in range(50)])
            detector._train_if_needed()
            self.assertEqual(thread.call_count, 2)

    def test_thread_start_failure_is_rate_limited_not_stuck_pending(self):
        detector, clock = self.detector()
        with patch('core.ids_ml.threading.Thread') as thread:
            thread.return_value.start.side_effect = RuntimeError('test')
            with self.assertRaises(RuntimeError):
                detector._train_if_needed()
            self.assertFalse(detector._training_pending)
            detector._train_if_needed()
            self.assertEqual(thread.call_count, 1)

    def test_existing_model_still_scores_packets_during_cooldown(self):
        detector, clock = self.detector()
        detector.sample_rate = 1
        detector._model = object()
        detector._trained = True
        detector._since_last_train = 300
        detector._last_train_attempt = 99
        packet = dict(src='10.0.0.1', dst='1.1.1.1', proto='TCP', sport=50000,
                      dport=443, length=1200, ttl=64)
        with patch.object(detector, '_score_model', return_value=.7) as score, \
                patch('core.ids_ml.threading.Thread') as thread:
            self.assertIsNotNone(detector.analyze_packet(packet))
            self.assertIsNotNone(detector.analyze_packet(packet))
            self.assertEqual(score.call_count, 1)
            thread.assert_not_called()

    def test_failed_fit_cannot_retry_on_every_packet(self):
        clock = Mock(return_value=100.0)
        detector = MLIDS(min_train_size=50, min_retrain_seconds=60, clock=clock)
        detector._buffer.extend([[1.0]*7 for _ in range(50)])
        numpy = Mock()
        numpy.asarray.side_effect = lambda samples, **kwargs: samples
        forest = Mock()
        forest.return_value.fit.side_effect = ValueError('test')
        with patch('core.ids_ml._load_numpy', return_value=numpy), \
                patch('core.ids_ml._load_isolation_forest', return_value=forest):
            detector._train_if_needed()
            for second in (101, 110, 159):
                clock.return_value = second
                detector._train_if_needed()
            self.assertEqual(forest.call_count, 1)
            clock.return_value = 160
            detector._train_if_needed()
            self.assertEqual(forest.call_count, 2)
        self.assertEqual(detector.training_stats()['training_failures'], 2)
