from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts.release import build_desktop_candidate as candidate


class CandidateBuildGuardTests(unittest.TestCase):
    def run_guard(self, process, *, size=0, clock=(0, 1)):
        owner = Mock()
        owner.children.return_value = []
        with tempfile.TemporaryDirectory(prefix='netbot-candidate-unit-') as folder:
            with patch.object(candidate.subprocess, 'Popen', return_value=process), \
                 patch.object(candidate.psutil, 'Process', return_value=owner), \
                 patch.object(candidate.psutil, 'wait_procs'), \
                 patch.object(candidate, 'folder_bytes', return_value=size), \
                 patch.object(candidate.shutil, 'disk_usage', return_value=SimpleNamespace(free=10 * candidate.GIB)), \
                 patch.object(candidate.time, 'monotonic', side_effect=clock), \
                 patch.object(candidate.time, 'sleep'):
                try:
                    candidate.guarded_run(['fixture-command'], Path(folder), Path(folder))
                finally:
                    self.owner = owner

    def test_success_does_not_terminate_completed_process(self):
        process = Mock(pid=123, returncode=0)
        process.poll.side_effect = [None, 0, 0]
        self.run_guard(process)
        self.owner.kill.assert_not_called()

    def test_storage_budget_terminates_only_owned_process(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        with self.assertRaisesRegex(RuntimeError, 'storage_budget_exceeded'):
            self.run_guard(process, size=3 * candidate.GIB + 1)
        self.owner.kill.assert_called_once()
        process.wait.assert_called_once_with(timeout=5)

    def test_deadline_terminates_owned_process(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        with self.assertRaisesRegex(RuntimeError, 'deadline_exceeded'):
            self.run_guard(process, clock=(0, 901))
        self.owner.kill.assert_called_once()

    def test_failed_build_is_not_reported_as_success(self):
        process = Mock(pid=123, returncode=1)
        process.poll.return_value = 1
        with self.assertRaisesRegex(RuntimeError, 'step_failed'):
            self.run_guard(process, clock=(0,))
        self.owner.kill.assert_not_called()


if __name__ == '__main__':
    unittest.main()
