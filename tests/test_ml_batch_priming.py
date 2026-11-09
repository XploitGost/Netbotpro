import threading
import unittest
from collections import Counter
from unittest.mock import Mock, patch

import numpy as np

from backend.app.services.sniffer_detection_pipeline import SnifferDetectionPipeline
from core.capture.process_session import ProcessCaptureSession
from core.flow_engine import FlowEngine
from core.ids_ml import MLIDS


def packets(count=32):
    return [{'proto': 'TCP', 'src': '10.0.0.5', 'dst': '8.8.8.8',
             'sport': 50000 + index, 'dport': 443, 'length': 100 + index,
             'ttl': 64, 'ts': '2026-11-08T12:00:00Z'} for index in range(count)]


class Model:
    def __init__(self, value=.1):
        self.value = value
        self.calls = []

    def decision_function(self, values):
        self.calls.append(len(values))
        return np.full(len(values), self.value)


def detector(model=None):
    result = MLIDS(sample_rate=5, min_train_size=10000)
    result._model = model or Model()
    result._trained = True
    return result


class BatchPrimingTests(unittest.TestCase):
    def test_prime_does_not_advance_sampling_training_or_buffer(self):
        ml = detector()
        ml.prime_scores(packets())
        self.assertEqual(ml._seen_packets, 0)
        self.assertEqual(len(ml._buffer), 0)
        self.assertEqual(ml.training_stats()['training_attempts'], 0)
        self.assertEqual(ml._model.calls, [6])
        self.assertEqual(len(ml._batch_keys), 6)

    def test_scalar_alerts_and_training_state_are_preserved(self):
        scalar, batched = detector(), detector()
        rows = packets(160)
        expected = [scalar.analyze_packet(row) for row in rows]
        actual = []
        for offset in range(0, len(rows), 32):
            batch = rows[offset:offset + 32]
            batched.prime_scores(batch)
            actual.extend(batched.analyze_packet(row) for row in batch)
        self.assertEqual(actual, expected)
        self.assertEqual(list(batched._buffer), list(scalar._buffer))
        self.assertEqual(batched._seen_packets, scalar._seen_packets)
        self.assertEqual(len(scalar._model.calls), 32)
        self.assertEqual(len(batched._model.calls), 5)

    def test_small_private_and_unsampled_packets_keep_existing_eligibility(self):
        ml = detector()
        rows = packets()
        for index in (4, 9, 14):
            rows[index]['length'] = 60
        for index in (19, 24, 29):
            rows[index]['dst'] = '10.0.0.8'
        ml.prime_scores(rows)
        self.assertEqual(ml._model.calls, [])
        self.assertEqual([ml.analyze_packet(row) for row in rows], [None] * 32)

    def test_near_threshold_scores_use_scalar_decision(self):
        ml = detector(Model(value=.25))
        ml.prime_scores(packets())
        for row in packets()[:5]:
            result = ml.analyze_packet(row)
        self.assertEqual(result['score'], .25)
        self.assertEqual(ml._model.calls, [6, 1])

    def test_failed_optional_batch_falls_back_but_scalar_error_remains_visible(self):
        ml = detector()
        with patch.object(ml._model, 'decision_function', side_effect=RuntimeError('failed')):
            ml.prime_scores(packets())
            self.assertEqual(ml.training_stats()['score_prime_failures'], 1)
            with self.assertRaises(RuntimeError):
                for row in packets()[:5]:
                    ml.analyze_packet(row)
        self.assertEqual(ml.training_stats()['scoring_errors_total'], 1)

    def test_model_replacement_and_reset_never_commit_old_precomputed_scores(self):
        ml = detector()
        original = ml._model
        replacement = Model(.2)
        def score(values):
            ml._model = replacement
            return np.full(len(values), .1)
        with patch.object(original, 'decision_function', side_effect=score):
            ml.prime_scores(packets())
        self.assertFalse(ml._batch_keys)
        for row in packets()[:5]:
            result = ml.analyze_packet(row)
        self.assertAlmostEqual(result['score'], .3)
        ml.prime_scores(packets())
        ml.reset_model()
        self.assertFalse(ml._batch_keys)
        self.assertFalse(ml._score_cache)
        self.assertEqual(ml.training_stats()['score_prime_batches'], 0)

    def test_batch_size_and_score_cache_are_bounded(self):
        ml = detector()
        ml.prime_scores(packets(300))
        self.assertEqual(ml._model.calls, [6])
        for batch in range(200):
            rows = packets()
            for row in rows:
                row['length'] += batch * 50
            ml.prime_scores(rows)
        self.assertLessEqual(len(ml._score_cache), 1024)
        self.assertLessEqual(len(ml._batch_keys), 1024)
        self.assertTrue(ml._batch_keys.issubset(ml._score_cache))

    def test_pipeline_respects_disabled_ml_and_optional_prepare_failures(self):
        ml = detector()
        pipeline = SnifferDetectionPipeline(ids_ml=ml, settings_provider=lambda: {'ids_ml_enabled': False})
        pipeline.prepare_batch(packets())
        self.assertFalse(ml._model.calls)
        pipeline._settings_provider = lambda: {'ids_ml_enabled': True}
        with patch.object(ml, 'prime_scores', side_effect=ValueError('bad metadata')):
            pipeline.prepare_batch(packets())
        self.assertEqual(pipeline.error_count(), 0)

    def test_journal_preparation_precedes_ordered_callbacks_and_ack(self):
        rows = packets(2)
        events = []
        session = ProcessCaptureSession(lambda row: events.append(row['sport']),
            prepare_batch=lambda batch: events.append('prepare'))
        session._journal = Mock()
        session._journal.first.side_effect = [(1, rows), None, None]
        session._journal.acknowledge.side_effect = lambda identifier: events.append('ack')
        session._process = Mock()
        session._process.is_alive.return_value = False
        session._stopping = threading.Event()
        session._stopping.set()
        session._receive_journal()
        self.assertEqual(events, ['prepare', 50000, 50001, 'ack'])
        session._process = object()
        with self.assertRaises(RuntimeError):
            session.set_batch_preparer(None)

    def test_flow_counter_snapshots_are_plain_detached_dicts(self):
        engine = FlowEngine()
        row = packets(1)[0]
        result = engine.ingest(row, [{'id': 'a1', 'severity': 'high'}], live_summary=True)
        self.assertIs(type(result['alert_counts']), dict)
        self.assertIsInstance(next(iter(engine._flows.values()))['alert_counts'], Counter)
        snapshot = engine.snapshot_flows([result['flow_id']])[0]
        self.assertIs(type(snapshot['alert_counts']), dict)
        snapshot['alert_counts']['high'] = 100
        self.assertEqual(engine.get_flow(result['flow_id'])['alert_counts']['high'], 1)


if __name__ == '__main__':
    unittest.main()
