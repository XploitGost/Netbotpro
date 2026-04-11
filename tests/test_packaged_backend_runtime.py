import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.qa import packaged_backend_smoke
from scripts.release import stage_backend_runtime


class PackagedBackendRuntimeTests(unittest.TestCase):
    def test_stage_backend_runtime_copies_full_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source_dir = root / "dist" / "netbotpro-backend"
            runtime_dir = root / "packaging" / "runtime" / "backend"
            source_dir.mkdir(parents=True)
            (source_dir / "netbotpro-backend.exe").write_text("exe", encoding="utf-8")
            (source_dir / "python313.dll").write_text("dll", encoding="utf-8")
            (source_dir / "config").mkdir()
            (source_dir / "config" / "settings.json").write_text("{}", encoding="utf-8")

            staged_binary = stage_backend_runtime.stage_runtime_bundle(source_dir, runtime_dir)

            self.assertEqual(staged_binary, runtime_dir / "netbotpro-backend.exe")
            self.assertTrue((runtime_dir / "netbotpro-backend.exe").exists())
            self.assertTrue((runtime_dir / "python313.dll").exists())
            self.assertTrue((runtime_dir / "config" / "settings.json").exists())

    def test_packaged_backend_smoke_finds_staged_binary(self):
        with tempfile.TemporaryDirectory() as td:
            runtime_dir = Path(td)
            binary = runtime_dir / "netbotpro-backend.exe"
            binary.write_text("exe", encoding="utf-8")
            support = runtime_dir / "python313.dll"
            support.write_text("dll", encoding="utf-8")

            with patch.object(packaged_backend_smoke, "PACKAGED_BACKEND_DIR", runtime_dir):
                found_binary = packaged_backend_smoke.find_binary()
                support_files = packaged_backend_smoke.list_support_files(runtime_dir)

            self.assertEqual(found_binary, binary)
            self.assertIn(support, support_files)


if __name__ == "__main__":
    unittest.main()
