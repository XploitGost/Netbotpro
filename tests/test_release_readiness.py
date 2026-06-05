import json
import re
import unittest
from pathlib import Path

from agent.agent_identity import AGENT_VERSION
from backend.app.main import app

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET_VERSION = "0.2.0"


class ReleaseReadinessTests(unittest.TestCase):
    def _read(self, relative_path: str) -> str:
        return (REPO_ROOT / relative_path).read_text(encoding="utf-8")

    def _json(self, relative_path: str) -> dict:
        return json.loads(self._read(relative_path))

    def test_version_consistency(self):
        frontend = self._json("frontend/package.json")
        frontend_lock = self._json("frontend/package-lock.json")
        electron = self._json("desktop/electron/package.json")
        electron_lock = self._json("desktop/electron/package-lock.json")
        changelog = self._read("CHANGELOG.md")

        self.assertEqual(app.version, TARGET_VERSION)
        self.assertEqual(AGENT_VERSION, TARGET_VERSION)
        self.assertEqual(frontend["version"], TARGET_VERSION)
        self.assertEqual(frontend_lock["version"], TARGET_VERSION)
        self.assertEqual(frontend_lock["packages"][""]["version"], TARGET_VERSION)
        self.assertEqual(electron["version"], TARGET_VERSION)
        self.assertEqual(electron_lock["version"], TARGET_VERSION)
        self.assertEqual(electron_lock["packages"][""]["version"], TARGET_VERSION)
        self.assertRegex(
            changelog,
            rf"## v{re.escape(TARGET_VERSION)} - Agent and Fleet Monitoring Release",
        )

    def test_demo_scripts_do_not_print_raw_tokens(self):
        for relative_path in [
            "scripts/dev/start-demo.ps1",
            "scripts/dev/seed-agent-demo.ps1",
        ]:
            script = self._read(relative_path)
            self.assertNotRegex(
                script, r'Write-Host\s+["(].*\$(DemoToken|AgentToken|SensorToken)'
            )
            self.assertNotIn('Write-Output "$DemoToken"', script)
            self.assertNotIn('Write-Output "$AgentToken"', script)

    def test_release_docs_exist_and_readme_links_them(self):
        readme = self._read("README.md")
        for relative_path in [
            "docs/DEPLOYMENT_OVERVIEW.md",
            "docs/RELEASE_QA_CHECKLIST.md",
        ]:
            self.assertTrue((REPO_ROOT / relative_path).is_file())
            self.assertIn(relative_path, readme)

    def test_agent_release_safety_is_explicit(self):
        combined = "\n".join(
            [
                self._read("docs/AGENT_MODE.md"),
                self._read("docs/RELEASE_QA_CHECKLIST.md"),
                self._read("docs/SAFE_USE_POLICY.md"),
            ]
        ).lower()

        self.assertIn("no command/control", combined)
        self.assertIn("no raw packet", combined)
        self.assertIn("raw payload", combined)
        self.assertIn("pcap forwarding", combined)
        self.assertIn("read-only monitoring", combined)

    def test_release_workflow_has_tags_notes_and_checksums(self):
        workflow = self._read(".github/workflows/release-desktop.yml")

        self.assertIn('- "v*"', workflow)
        self.assertIn("SHA256SUMS-windows.txt", workflow)
        self.assertIn("SHA256SUMS-linux.txt", workflow)
        self.assertIn("body_path: CHANGELOG.md", workflow)
        self.assertIn("Netbotpro-*.exe", workflow)


if __name__ == "__main__":
    unittest.main()
