import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "repository_hygiene", Path(__file__).resolve().parents[1] / "scripts/qa/repository_hygiene.py")
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)


class RepositoryHygieneTests(unittest.TestCase):
    def test_source_and_env_templates_are_allowed(self):
        for name in ("core/flow_engine.py", ".env.example", "deploy/netbot.env.example"):
            self.assertEqual(hygiene.check_file(name, b"example source"), [])

    def test_runtime_and_credentials_are_rejected(self):
        for name in (".env", ".env.local", "core/native-redaction-build.json", "dump.pcapng",
                     ".runtime/status.json", "frontend/node_modules/a.js", "backend.exe"):
            self.assertTrue(hygiene.check_file(name, b"data"), name)

    def test_secret_patterns_do_not_echo_values(self):
        values = [b"ghp_" + b"a" * 36, b"github_pat_" + b"b" * 50,
                  b"AKIA" + b"A" * 16, b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----"]
        for value in values:
            result = hygiene.check_file("source.py", value)
            self.assertTrue(result)
            self.assertNotIn(value.decode(), str(result))

    def test_large_source_requires_review(self):
        self.assertTrue(hygiene.check_file("data.bin", b"x" * (hygiene.MAX_SOURCE_BYTES + 1)))

    def test_index_check_reads_staged_not_worktree_and_ignores_untracked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            source = root / "source.py"
            source.write_text("safe", encoding="utf-8")
            subprocess.run(["git", "add", "source.py"], cwd=root, check=True)
            source.write_text("ghp_" + "a" * 36, encoding="utf-8")
            (root / ".env").write_text("untracked", encoding="utf-8")
            self.assertEqual(hygiene.check_repository(root, staged=True), [])
            self.assertEqual(len(hygiene.check_repository(root)), 1)
