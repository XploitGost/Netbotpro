import unittest
from unittest.mock import patch

from backend.app.services import settings_service


class SettingsServiceTests(unittest.TestCase):
    @patch("backend.app.services.settings_service.init_storage")
    @patch("backend.app.services.settings_service.set_persist")
    @patch("backend.app.services.settings_service.save_settings")
    def test_update_settings_uses_cache_and_applies_runtime_state(self, mock_save, mock_set_persist, mock_init_storage):
        original = settings_service.get_settings_snapshot()
        try:
            settings_service._replace_cache(
                {
                    **original,
                    "persist_logs": False,
                    "ids_ml_threshold": 0.25,
                    "iface": "iface=default",
                }
            )

            updated = settings_service.update_settings(
                {
                    "persist_logs": True,
                    "ids_ml_threshold": 9,
                    "iface": "Ethernet 1",
                }
            )

            self.assertTrue(updated["persist_logs"])
            self.assertEqual(updated["ids_ml_threshold"], 1.0)
            self.assertEqual(settings_service.get_settings()["iface"], "Ethernet 1")
            mock_save.assert_called_once()
            mock_set_persist.assert_called_with(True)
            mock_init_storage.assert_called_once()
        finally:
            settings_service._replace_cache(original)


if __name__ == "__main__":
    unittest.main()
