import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

from scripts.qa.packaged_backend_smoke import run_runtime_probes


class PackagedFeatureProbeTests(unittest.TestCase):
    def run_probes(self, ml, exports):
        values = [Mock(stdout=json.dumps(ml)), Mock(stdout=json.dumps(exports))]
        with patch("scripts.qa.packaged_backend_smoke.find_binary", return_value=Path("backend.exe")), \
             patch("scripts.qa.packaged_backend_smoke.subprocess.run", side_effect=values) as run:
            run_runtime_probes(Path("unused"))
            self.assertEqual(run.call_count, 2)
            for call in run.call_args_list:
                self.assertTrue(call.kwargs["check"])
                self.assertEqual(call.kwargs["timeout"], 90)

    def test_all_packaged_features_must_pass(self):
        self.run_probes({"ml_available": True, "trained": True},
                        dict.fromkeys(("csv", "xlsx", "pdf", "html", "zip"), "ok"))

    def test_optional_ml_fallback_is_not_a_pass(self):
        with self.assertRaisesRegex(AssertionError, "ML"):
            self.run_probes({"ml_available": False, "trained": False}, {})

    def test_missing_export_is_not_a_pass(self):
        with self.assertRaisesRegex(AssertionError, "export"):
            self.run_probes({"ml_available": True, "trained": True}, {"csv": "ok"})

    def test_failed_binary_is_not_ignored(self):
        with patch("scripts.qa.packaged_backend_smoke.find_binary", return_value=Path("backend.exe")), \
             patch("scripts.qa.packaged_backend_smoke.subprocess.run",
                   side_effect=subprocess.CalledProcessError(1, "probe")):
            with self.assertRaises(subprocess.CalledProcessError):
                run_runtime_probes()
