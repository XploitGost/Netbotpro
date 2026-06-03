import os
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from backend.app.services.capture_policy import current_capture_policy, enforce_capture_policy


class CapturePolicyTests(unittest.TestCase):
    @patch("backend.app.services.capture_policy.get_settings_snapshot", return_value={})
    def test_metadata_mode_allows_local_dev_without_safe_use(self, _mock_settings):
        with patch.dict(os.environ, {"NETBOT_CAPTURE_MODE": "metadata", "NETBOT_SAFE_USE_ACCEPTED": "0", "NETBOT_ALLOW_FULL_CAPTURE": "0"}, clear=False):
            policy = enforce_capture_policy({"capture_mode": "metadata"})

        self.assertEqual(policy.mode, "metadata")
        self.assertFalse(policy.payload_capture_enabled)

    @patch("backend.app.services.capture_policy.get_settings_snapshot", return_value={})
    def test_full_mode_requires_safe_use(self, _mock_settings):
        with patch.dict(os.environ, {"NETBOT_ALLOW_FULL_CAPTURE": "1", "NETBOT_SAFE_USE_ACCEPTED": "0"}, clear=False):
            with self.assertRaises(HTTPException) as ctx:
                enforce_capture_policy({"capture_mode": "full"})

        self.assertEqual(ctx.exception.status_code, 451)

    @patch("backend.app.services.capture_policy.get_settings_snapshot", return_value={})
    def test_full_mode_requires_allow_full_capture(self, _mock_settings):
        with patch.dict(os.environ, {"NETBOT_ALLOW_FULL_CAPTURE": "0", "NETBOT_SAFE_USE_ACCEPTED": "1"}, clear=False):
            with self.assertRaises(HTTPException) as ctx:
                enforce_capture_policy({"capture_mode": "full"})

        self.assertEqual(ctx.exception.status_code, 403)

    @patch("backend.app.services.capture_policy.get_settings_snapshot", return_value={})
    def test_full_mode_accepts_explicit_authorization(self, _mock_settings):
        with patch.dict(os.environ, {"NETBOT_ALLOW_FULL_CAPTURE": "1", "NETBOT_SAFE_USE_ACCEPTED": "1", "NETBOT_PAYLOAD_CAPTURE": "1"}, clear=False):
            policy = enforce_capture_policy({"capture_mode": "full"})

        self.assertEqual(policy.mode, "full")
        self.assertTrue(policy.payload_capture_enabled)

    @patch("backend.app.services.capture_policy.get_settings_snapshot", return_value={})
    def test_forensic_mode_requires_duration_or_explicit_confirmation(self, _mock_settings):
        with patch.dict(os.environ, {"NETBOT_ALLOW_FULL_CAPTURE": "1", "NETBOT_SAFE_USE_ACCEPTED": "1"}, clear=False):
            with self.assertRaises(HTTPException) as ctx:
                enforce_capture_policy({"capture_mode": "forensic"})
            policy = enforce_capture_policy({"capture_mode": "forensic", "forensic_duration_minutes": 15})

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(policy.mode, "forensic")
        self.assertEqual(policy.forensic_duration_minutes, 15)

    @patch("backend.app.services.capture_policy.get_settings_snapshot", return_value={"capture_mode": "full", "allow_full_capture": True, "safe_use_policy_accepted": True})
    def test_settings_can_supply_capture_policy(self, _mock_settings):
        policy = current_capture_policy({})

        self.assertEqual(policy.mode, "full")
        self.assertTrue(policy.allow_full_capture)


if __name__ == "__main__":
    unittest.main()
