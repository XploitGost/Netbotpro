import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = REPO_ROOT / "scripts" / "dev"


class SensorScriptTests(unittest.TestCase):
    def _read_script(self, name: str) -> str:
        return (SCRIPT_DIR / name).read_text(encoding="utf-8")

    def test_start_sensor_hides_token_without_show_token(self):
        script = self._read_script("start-sensor.ps1")

        self.assertIn("[switch]$ShowToken", script)
        self.assertIn('Write-Host "Token file: $TokenFile"', script)
        self.assertIn(
            'if ($ShowToken) {\n    Write-Host "Token: $SensorToken"\n}', script
        )
        self.assertNotIn("Token: <hidden", script)

    def test_start_sensor_prints_token_only_with_show_token_block(self):
        script = self._read_script("start-sensor.ps1")
        token_print = 'Write-Host "Token: $SensorToken"'

        self.assertEqual(script.count(token_print), 1)
        self.assertIn("if ($ShowToken)", script)
        self.assertLess(script.index("if ($ShowToken)"), script.index(token_print))

    def test_sensor_scripts_share_pid_and_log_paths(self):
        expected_fragments = [
            '$PidFile = Join-Path $RuntimeDir "sensor-backend.pid"',
            '$LogDir = Join-Path $RuntimeDir "logs"',
            '$StdoutLog = Join-Path $LogDir "sensor-backend.log"',
            '$StderrLog = Join-Path $LogDir "sensor-backend.err.log"',
        ]

        for name in ["start-sensor.ps1", "status-sensor.ps1", "stop-sensor.ps1"]:
            script = self._read_script(name)
            for fragment in expected_fragments:
                self.assertIn(fragment, script, f"{name} missing {fragment}")

    def test_status_sensor_never_prints_raw_token(self):
        script = self._read_script("status-sensor.ps1")

        self.assertIn('Write-Host "Token file: $TokenFile"', script)
        self.assertNotIn("$SensorToken", script)
        self.assertNotIn("$env:NETBOT_LOCAL_TOKEN", script)
        self.assertNotIn('Write-Host "Token:', script)

    def test_status_sensor_removes_stale_pid_file(self):
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if not powershell:
            self.skipTest("PowerShell is not available")

        with tempfile.TemporaryDirectory() as td:
            temp_root = Path(td)
            temp_script_dir = temp_root / "scripts" / "dev"
            temp_runtime = temp_root / ".runtime"
            temp_script_dir.mkdir(parents=True)
            temp_runtime.mkdir()
            script_path = temp_script_dir / "status-sensor.ps1"
            shutil.copy2(SCRIPT_DIR / "status-sensor.ps1", script_path)
            pid_file = temp_runtime / "sensor-backend.pid"
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


if __name__ == "__main__":
    unittest.main()
