import os
import tempfile
import unittest
from pathlib import Path
from importlib import reload
from unittest.mock import patch

import backend.app.bootstrap as bootstrap
import config.settings_manager as settings_manager
import core.netbotpro_logging.config as logging_config


class DesktopPathTests(unittest.TestCase):
    def test_settings_manager_respects_desktop_config_dir(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"NETBOT_CONFIG_DIR": td}, clear=False):
                reloaded = reload(settings_manager)
                self.assertEqual(reloaded.BASE_DIR, td)
                self.assertTrue(reloaded.SETTINGS_PATH.startswith(td))

    def test_logging_config_respects_desktop_data_dir(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"NETBOT_DATA_DIR": td, "NETBOT_LOG_DIR": os.path.join(td, "logs")}, clear=False):
                reloaded = reload(logging_config)
                self.assertTrue(reloaded.DB_PATH.startswith(td))
                self.assertEqual(str(reloaded.LOG_DIR), os.path.join(td, "logs"))

    def test_bootstrap_uses_writable_desktop_cache_dir(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.dict(os.environ, {"NETBOT_DATA_DIR": td, "NETBOT_CACHE_DIR": "", "SCAPY_CACHE_FOLDER": ""}, clear=False):
                reloaded = reload(bootstrap)
                cache_root = reloaded.runtime_cache_root()
                project_root = reloaded.ensure_project_root_on_path()
                self.assertEqual(cache_root, Path(td) / "cache")
                self.assertEqual(Path(os.environ["SCAPY_CACHE_FOLDER"]), cache_root / "scapy")
                self.assertEqual(Path(os.environ["NETBOT_CACHE_DIR"]), cache_root)
                self.assertEqual(project_root, Path(reloaded.__file__).resolve().parents[2])


if __name__ == "__main__":
    unittest.main()
