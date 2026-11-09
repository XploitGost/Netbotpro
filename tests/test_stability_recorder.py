import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from backend.app.services.stability_recorder import StabilityRecorder, project


def snapshot(received=10, pending=0):
    return dict(capture=dict(running=True, capture_started_at=123,
                ipc_received=received, ipc_delivered=received-pending,
                ipc_pending=pending, ipc_dropped=0,
                secret='DO-NOT-RECORD', selected_iface='private-network',
                driver_stats=dict(available=True, coverage_complete=True,
                                  buffer_dropped_reported=0)),
                packet=dict(src='private-ip', token='DO-NOT-RECORD'))


class StabilityRecorderTests(unittest.TestCase):
    def test_compaction_error_is_recorded_without_sensitive_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            source = snapshot()
            source['flow_memory'] = {'errors_total': 1, 'compressed_flows': 4, 'secret': 'DO-NOT-RECORD'}
            recorder = StabilityRecorder(lambda: source, Path(folder) / 's.jsonl', resources=self.usage)
            recorder.sample()
            self.assertEqual(recorder.stats()['assessment'], 'needs_review')
            self.assertNotIn('DO-NOT-RECORD', (Path(folder) / 's.jsonl').read_text())

    @staticmethod
    def usage(pid):
        return dict(backend_rss_bytes=100, capture_rss_bytes=50,
                    backend_cpu_seconds=1, capture_cpu_seconds=1, backend_pid=1, capture_pid=2)

    def test_warmup_unknown_does_not_prevent_a_later_continuous_window(self):
        with tempfile.TemporaryDirectory() as folder:
            source = snapshot()
            ticks = iter((0, 5, 10, 15))
            recorder = StabilityRecorder(lambda: source, Path(folder) / 's.jsonl',
                                         clock=lambda: next(ticks), resources=self.usage)
            recorder._summary['target_seconds'] = 10
            recorder.sample()
            source['capture']['driver_stats']['sample_age_seconds'] = 0
            for _ in range(3):
                recorder.sample()
            self.assertEqual(recorder.stats()['qualified_continuous_seconds'], 10)
            self.assertEqual(recorder.stats()['assessment'], 'ready_for_review')
            self.assertEqual(recorder.stats()['driver_incomplete_samples'], 1)

    def test_sampling_gap_is_visible_and_not_counted_as_continuous_time_or_rate(self):
        with tempfile.TemporaryDirectory() as folder:
            source = snapshot()
            source['capture']['driver_stats'].update(sample_age_seconds=0, samples=10)
            ticks = iter((0, 5, 100))
            recorder = StabilityRecorder(lambda: source, Path(folder) / 's.jsonl',
                                         clock=lambda: next(ticks), resources=self.usage)
            recorder.sample()
            recorder.sample()
            source['capture']['ipc_received'] = source['capture']['ipc_delivered'] = 30
            source['capture']['driver_stats']['samples'] = 12
            recorder.sample()
            summary = recorder.stats()
            self.assertEqual(summary['qualified_continuous_seconds'], 0)
            self.assertEqual(summary['unobserved_seconds_total'], 95)
            self.assertEqual(summary['last_gap_received_delta'], 20)
            self.assertEqual(summary['last_gap_driver_samples_delta'], 2)
            self.assertEqual(summary['health'], 'degraded')
            self.assertEqual(summary['assessment'], 'needs_review')
            row = json.loads((Path(folder) / 's.jsonl').read_text().splitlines()[-1])
            self.assertIsNone(row['received_per_second'])

    def test_backlog_and_new_session_reset_the_qualified_window(self):
        with tempfile.TemporaryDirectory() as folder:
            source = snapshot()
            source['capture']['driver_stats']['sample_age_seconds'] = 0
            source['capture']['journal_backlog_warning_records'] = 10
            ticks = iter((0, 5, 10, 15, 20, 25))
            recorder = StabilityRecorder(lambda: source, Path(folder) / 's.jsonl',
                                         clock=lambda: next(ticks), resources=self.usage)
            recorder.sample()
            recorder.sample()
            source['capture']['ipc_pending'] = 10
            recorder.sample()
            self.assertEqual(recorder.stats()['qualified_continuous_seconds'], 0)
            source['capture']['ipc_pending'] = 0
            recorder.sample()
            recorder.sample()
            self.assertEqual(recorder.stats()['qualified_continuous_seconds'], 5)
            source['capture']['capture_started_at'] = 999
            recorder.sample()
            self.assertEqual(recorder.stats()['qualified_continuous_seconds'], 0)
            self.assertEqual(recorder.stats()['assessment'], 'needs_review')

    def test_numeric_projection_does_not_retain_packet_data(self):
        row = project(snapshot())
        serialized = json.dumps(row)
        self.assertNotIn('private', serialized)
        self.assertNotIn('DO-NOT-RECORD', serialized)
        self.assertIsNone(row['driver_interface_dropped_raw'])
        source = snapshot()
        source['capture']['ipc_received'] = float('nan')
        self.assertIsNone(project(source)['received'])

    def test_rates_rotation_and_summary_are_bounded_and_not_automatic_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'stability.jsonl'
            source = Mock(side_effect=[snapshot(10), snapshot(30, 5)] + [snapshot(40)]*10)
            ticks = iter(range(0, 60, 5))
            usage = lambda pid: dict(backend_rss_bytes=100, capture_rss_bytes=50,
                                    backend_cpu_seconds=1, capture_cpu_seconds=1,
                                    backend_pid=1, capture_pid=2)
            recorder = StabilityRecorder(source, path, max_bytes=1024, backups=2,
                clock=lambda: next(ticks), resources=usage)
            for _ in range(12):
                recorder.sample()
            summary = recorder.stats()
            self.assertEqual(summary['samples'], 12)
            self.assertEqual(summary['max_pending'], 5)
            self.assertEqual(summary['assessment'], 'incomplete')
            self.assertEqual(summary['write_errors'], 0)
            self.assertLessEqual(len(list(Path(folder).glob('stability.jsonl*'))), 3)
            for file in Path(folder).iterdir():
                self.assertNotIn('DO-NOT-RECORD', file.read_text())
                self.assertNotIn('private', file.read_text())

    def test_missing_stats_and_resource_errors_are_visible(self):
        with tempfile.TemporaryDirectory() as folder:
            source = snapshot()
            source['capture']['driver_stats'] = {}
            recorder = StabilityRecorder(lambda:source, Path(folder)/'s.jsonl', resources=lambda pid:{})
            recorder.sample()
            self.assertEqual(recorder.stats()['driver_unknown_samples'], 1)
            self.assertEqual(recorder.stats()['resource_unknown_samples'], 1)
            recorder._write = Mock(side_effect=OSError('private path'))
            recorder.sample()
            self.assertEqual(recorder.stats()['write_errors'], 1)
            self.assertEqual(recorder.stats()['last_error_type'], 'OSError')
            self.assertEqual(recorder.stats()['assessment'], 'needs_review')

    def test_reported_drop_is_sticky_and_thread_stops(self):
        with tempfile.TemporaryDirectory() as folder:
            source = snapshot()
            source['capture']['driver_stats']['buffer_dropped_reported'] = 2
            recorder = StabilityRecorder(lambda:source, Path(folder)/'s.jsonl', interval=.1, resources=lambda pid:{})
            recorder.sample()
            source['capture']['driver_stats']['buffer_dropped_reported'] = 0
            recorder.sample()
            self.assertTrue(recorder.stats()['issues_observed'])
            self.assertEqual(recorder.stats()['assessment'], 'needs_review')
            recorder.start()
            recorder.close()
            self.assertFalse(recorder._thread.is_alive())
