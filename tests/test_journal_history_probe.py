import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts.qa.journal_history_probe import (
    isolated_environment, run_probe, stop_owned_tree, verify_counts, workspace_bytes,
)


class JournalHistoryProbeTests(unittest.TestCase):
    def test_environment_is_detached_and_routes_all_probe_databases(self):
        before = dict(os.environ)
        env = isolated_environment(Path('probe-workspace').resolve(), 123)
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(env['NETBOT_JOURNAL_ACK_MODE'], 'history')
        self.assertEqual(env['NETBOT_PROBE_RATE'], '123')
        for key in ('NETBOT_DB_PATH', 'NETBOT_FLOW_DB_PATH', 'NETBOT_CAPTURE_JOURNAL_PATH',
                    'NETBOT_DATA_DIR', 'NETBOT_LOG_DIR', 'NETBOT_CONFIG_DIR'):
            self.assertTrue(Path(env[key]).is_relative_to(Path('probe-workspace').resolve()))

    def test_missing_or_inconsistent_counts_cannot_report_success(self):
        good = dict(ipc_accepted=3, journal_acknowledged_records=3, journal_pending_records=0)
        self.assertEqual(verify_counts(good, {'persisted_packets': 3}, 3), [])
        self.assertTrue(verify_counts({}, {}, 0))
        for key, value in (('ipc_accepted', 4), ('journal_pending_records', 1),
                           ('ipc_callback_errors', 1), ('ipc_dropped', 1), ('capture_error', 'fixture')):
            self.assertTrue(verify_counts({**good, key: value}, {'persisted_packets': 3}, 3))
        for key in ('failed_writes', 'dropped_writes', 'skipped_writes'):
            self.assertTrue(verify_counts(good, {'persisted_packets': 3, key: 1}, 3))
        self.assertTrue(verify_counts({**good, 'driver_stats': {'buffer_dropped_reported': 1}},
                                      {'persisted_packets': 3}, 3))

    def test_probe_rejects_oversized_work_before_launch(self):
        for args in ({'duration': 0}, {'duration': 121}, {'duration': float('nan')},
                     {'rate': 0}, {'rate': 501}, {'max_bytes': 0}, {'max_bytes': 65 * 1024**2}):
            with self.assertRaises(ValueError):
                run_probe(**args)

    def test_supervisor_kills_only_its_worker_tree_in_reverse_order(self):
        process, parent, first, last = Mock(pid=123), Mock(), Mock(), Mock()
        parent.children.return_value = [first, last]
        calls = []
        for item, name in ((parent, 'parent'), (first, 'first'), (last, 'last')):
            item.kill.side_effect = lambda name=name: calls.append(name)
        with patch('scripts.qa.journal_history_probe.psutil.Process', return_value=parent) as lookup, \
             patch('scripts.qa.journal_history_probe.psutil.wait_procs'):
            stop_owned_tree(process)
        lookup.assert_called_once_with(123)
        self.assertEqual(calls, ['last', 'first', 'parent'])

    def test_workspace_size_uses_only_its_temporary_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(workspace_bytes(Path(temporary)), 0)

    @unittest.skipUnless(os.name == 'nt', 'DPAPI requires Windows')
    def test_synthetic_service_probe_drains_and_removes_scratch_data(self):
        report = run_probe(duration=1, rate=64)
        self.assertTrue(report['ok'], report)
        self.assertEqual(report['accepted'], report['history_rows'])
        self.assertEqual(report['pending_final'], 0)
        self.assertTrue(report['temporary_workspace_removed'])
        self.assertLess(report['temporary_peak_bytes'], 64 * 1024**2)
