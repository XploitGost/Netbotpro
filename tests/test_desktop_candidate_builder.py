from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts.release import build_desktop_candidate as candidate


class CandidateBuildGuardTests(unittest.TestCase):
    def test_repeated_builds_cannot_accumulate_unbounded_artifacts(self):
        with patch.object(candidate, 'folder_bytes', return_value=2 * candidate.GIB + 1), \
             patch.object(candidate, 'shutil', SimpleNamespace(disk_usage=lambda _: SimpleNamespace(free=10 * candidate.GIB))):
            with self.assertRaisesRegex(RuntimeError, 'cache_budget_exceeded'):
                candidate.check_build_admission(Path.cwd())

    def test_admission_requires_free_disk_headroom(self):
        with patch.object(candidate, 'shutil', SimpleNamespace(disk_usage=lambda _: SimpleNamespace(free=candidate.GIB))):
            with self.assertRaisesRegex(RuntimeError, '5 GiB'):
                candidate.check_build_admission(Path.cwd())

    def run_guard(self, process, *, size=0, clock=(0, 1)):
        owner = Mock()
        owner.children.return_value = []
        real_clock = time.monotonic
        process_api = SimpleNamespace(Process=Mock(return_value=owner), wait_procs=Mock(), NoSuchProcess=candidate.psutil.NoSuchProcess)
        subprocess_api = SimpleNamespace(Popen=Mock(return_value=process), STDOUT=candidate.subprocess.STDOUT)
        clock_api = SimpleNamespace(monotonic=Mock(side_effect=clock), sleep=Mock())
        with tempfile.TemporaryDirectory(prefix='netbot-candidate-unit-') as folder:
            with patch.object(candidate, 'subprocess', subprocess_api), \
                 patch.object(candidate, 'psutil', process_api), \
                 patch.object(candidate, 'folder_bytes', return_value=size), \
                 patch.object(candidate, 'shutil', SimpleNamespace(disk_usage=lambda _: SimpleNamespace(free=10 * candidate.GIB))), \
                 patch.object(candidate, 'time', clock_api):
                try:
                    self.assertIs(time.monotonic, real_clock)
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
