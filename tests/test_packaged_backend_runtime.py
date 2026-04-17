import os
import tempfile
import unittest
from pathlib import Path
import json

from scripts.qa import packaged_backend_smoke
from scripts.release import stage_backend_runtime


class PackagedBackendRuntimeTests(unittest.TestCase):
    def test_stage_backend_runtime_copies_full_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            bundle_dir = repo_root / "dist" / "netbotpro-backend"
            runtime_dir = repo_root / "packaging" / "runtime" / "backend"
            bundle_dir.mkdir(parents=True)

            binary_name = stage_backend_runtime.expected_binary_name("win32" if os.name == "nt" else "linux")
            (bundle_dir / binary_name).write_text("binary", encoding="utf-8")
            (bundle_dir / "support.dll").write_text("support", encoding="utf-8")
            (bundle_dir / "data").mkdir()
            (bundle_dir / "data" / "config.json").write_text("{}", encoding="utf-8")

            staged_binary = stage_backend_runtime.stage_backend_runtime(bundle_dir, runtime_dir)

            self.assertEqual(staged_binary, runtime_dir / binary_name)
            self.assertTrue((runtime_dir / "support.dll").exists())
            self.assertTrue((runtime_dir / "data" / "config.json").exists())

    def test_packaged_backend_smoke_helpers_find_bundle_and_status_leak(self):
        with tempfile.TemporaryDirectory() as td:
            runtime_dir = Path(td) / "packaging" / "runtime" / "backend"
            runtime_dir.mkdir(parents=True)

            binary = runtime_dir / packaged_backend_smoke.expected_binary_name("win32" if os.name == "nt" else "linux")
            binary.write_text("binary", encoding="utf-8")
            support = runtime_dir / "python313.dll"
            support.write_text("support", encoding="utf-8")

            found_binary = packaged_backend_smoke.find_binary(runtime_dir)
            support_files = packaged_backend_smoke.list_support_files(runtime_dir)

            self.assertEqual(found_binary, binary)
            self.assertIn(support, support_files)

            packaged_backend_smoke.validate_status_payload({"ok": True, "sniffer": {}})
            packaged_backend_smoke.validate_interfaces_payload({"items": [], "degraded": True, "source": "fallback", "reason": "interface_discovery_timeout"})
            with self.assertRaises(AssertionError):
                packaged_backend_smoke.validate_status_payload({"ok": True, "project_root": "C:/secret"})
            with self.assertRaises(AssertionError):
                packaged_backend_smoke.validate_interfaces_payload({"items": [], "degraded": True, "source": "fallback"})

    def test_desktop_package_supports_cross_platform_dist_scripts(self):
        package_json = Path(__file__).resolve().parents[1] / "desktop" / "electron" / "package.json"
        data = json.loads(package_json.read_text(encoding="utf-8"))

        scripts = data.get("scripts", {})
        self.assertIn("dist:win", scripts)
        self.assertIn("dist:linux", scripts)
        self.assertNotIn("electronDist", data.get("build", {}))
        self.assertEqual(data.get("build", {}).get("linux", {}).get("target"), ["AppImage", "deb"])


if __name__ == "__main__":
    unittest.main()
