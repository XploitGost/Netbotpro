import os
import tempfile
import unittest
from importlib import reload
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
