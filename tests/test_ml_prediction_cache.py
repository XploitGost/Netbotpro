import unittest
from unittest.mock import patch
from core.ids_ml import MLIDS


class PredictionCacheTests(unittest.TestCase):
    def test_exact_features_reuse_score_and_model_change_invalidates(self):
        detector = MLIDS()
        first, second = object(), object()
        with patch.object(detector, '_score_model', return_value=0.7) as score:
            self.assertEqual(detector._cached_model_score(first, [1, 2]), 0.7)
            self.assertEqual(detector._cached_model_score(first, [1, 2]), 0.7)
            self.assertEqual(score.call_count, 1)
            detector._cached_model_score(first, [1, 3])
            detector._cached_model_score(second, [1, 2])
            self.assertEqual(score.call_count, 3)

    def test_cache_is_bounded_and_reset_clears_it(self):
        detector = MLIDS()
        model = object()
        with patch.object(detector, '_score_model', return_value=0):
            for number in range(1100):
                detector._cached_model_score(model, [number])
        self.assertEqual(len(detector._score_cache), 1024)
        detector.reset_model()
        self.assertFalse(detector._score_cache)
