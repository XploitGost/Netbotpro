import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = REPO_ROOT / "scripts" / "dev"


class AgentScriptTests(unittest.TestCase):
    def _read_script(self, name: str) -> str:
        return (SCRIPT_DIR / name).read_text(encoding="utf-8")

    def test_agent_scripts_share_pid_and_log_paths(self):
        expected_fragments = [
            '$PidFile = Join-Path $RuntimeDir "agent-runner.pid"',
            '$LogDir = Join-Path $RuntimeDir "logs"',
            '$StdoutLog = Join-Path $LogDir "agent-runner.log"',
            '$StderrLog = Join-Path $LogDir "agent-runner.err.log"',
        ]

        for name in ["start-agent.ps1", "status-agent.ps1", "stop-agent.ps1"]:
            script = self._read_script(name)
            for fragment in expected_fragments:
                self.assertIn(fragment, script, f"{name} missing {fragment}")

    def test_agent_scripts_do_not_print_raw_token(self):
        start_script = self._read_script("start-agent.ps1")
        status_script = self._read_script("status-agent.ps1")

        self.assertIn("Agent token is configured and hidden.", start_script)
        self.assertIn(
            "Agent token is never printed by this status command.",
            status_script,
        )
        for script in [start_script, status_script]:
            self.assertNotIn('Write-Host "Agent token: $AgentToken"', script)
            self.assertNotIn('Write-Host ("Agent token:', script)
            self.assertNotIn("Agent token: <hidden>", script)

    def test_status_agent_removes_stale_pid_file(self):
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if not powershell:
            self.skipTest("PowerShell is not available")

        with tempfile.TemporaryDirectory() as td:
            temp_root = Path(td)
            temp_script_dir = temp_root / "scripts" / "dev"
            temp_runtime = temp_root / ".runtime"
            temp_script_dir.mkdir(parents=True)
            temp_runtime.mkdir()
            script_path = temp_script_dir / "status-agent.ps1"
            shutil.copy2(SCRIPT_DIR / "status-agent.ps1", script_path)
            pid_file = temp_runtime / "agent-runner.pid"
            pid_file.write_text("not-a-pid", encoding="ascii")

            completed = subprocess.run(
                [
                    powershell,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            pid_exists_after_run = pid_file.exists()

        self.assertEqual(completed.returncode, 1)
        self.assertIn("invalid stale PID file removed", completed.stdout)
        self.assertFalse(pid_exists_after_run)

    def test_demo_and_cleanup_scripts_do_not_print_tokens(self):
        for name in [
            "seed-agent-demo.ps1",
            "start-agent-demo-fleet.ps1",
            "status-agent-demo-fleet.ps1",
            "stop-agent-demo-fleet.ps1",
            "cleanup-agent-history.ps1",
        ]:
            script = self._read_script(name)
            self.assertNotIn('Write-Host "Agent token: $AgentToken"', script)
            self.assertNotIn('Write-Host "Token:', script)
            self.assertIn(
                "tokens", script.lower(), f"{name} should state tokens are hidden"
            )

    def test_demo_fleet_scripts_use_shared_runtime_and_separate_logs(self):
        start_script = self._read_script("start-agent-demo-fleet.ps1")
        status_script = self._read_script("status-agent-demo-fleet.ps1")
        stop_script = self._read_script("stop-agent-demo-fleet.ps1")

        for script in [start_script, status_script, stop_script]:
            self.assertIn('"agent-demo-fleet"', script)
            self.assertIn('"logs"', script)
        self.assertIn("NETBOT_AGENT_DISPLAY_NAME", start_script)
        self.assertIn("Remove-Item -Force $PidFile", stop_script)

    def test_cleanup_agent_history_supports_dry_run(self):
        script = self._read_script("cleanup-agent-history.ps1")

        self.assertIn("[switch]$DryRun", script)
        self.assertIn("cleanup_agent_history", script)
        self.assertIn("RetentionDays", script)


if __name__ == "__main__":
    unittest.main()
