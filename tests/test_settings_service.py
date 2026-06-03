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

    @patch("backend.app.services.settings_service.init_storage")
    @patch("backend.app.services.settings_service.set_persist")
    @patch("backend.app.services.settings_service.save_settings")
    def test_update_settings_sanitizes_iface_and_whitelist(self, mock_save, mock_set_persist, mock_init_storage):
        original = settings_service.get_settings_snapshot()
        try:
            settings_service._replace_cache(dict(original))

            updated = settings_service.update_settings(
                {
                    "iface": "Wi-Fi 1\r\nInjected",
                    "whitelist_ips": "127.0.0.1, bad-ip, ::1, 127.0.0.1",
                    "remote_dashboard_allowlist": "10.0.0.5, bad-cidr, 192.168.1.0/24",
                    "payload_capture_enabled": True,
                    "alert_only_mode": True,
                    "safe_use_policy_accepted": True,
                    "retention_minutes": 120,
                }
            )

            self.assertEqual(updated["iface"], "Wi-Fi 1Injected")
            self.assertEqual(updated["whitelist_ips"], "127.0.0.1, ::1")
            self.assertEqual(updated["remote_dashboard_allowlist"], "10.0.0.5, 192.168.1.0/24")
            self.assertTrue(updated["payload_capture_enabled"])
            self.assertTrue(updated["alert_only_mode"])
            self.assertTrue(updated["safe_use_policy_accepted"])
            self.assertEqual(updated["retention_minutes"], 120)
            mock_save.assert_called_once()
            mock_set_persist.assert_called_once_with(bool(updated.get("persist_logs")))
            if updated.get("persist_logs"):
                mock_init_storage.assert_called_once()
            else:
                mock_init_storage.assert_not_called()
        finally:
            settings_service._replace_cache(original)


if __name__ == "__main__":
    unittest.main()
