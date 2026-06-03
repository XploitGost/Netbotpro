import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from backend.app import main
from backend.app.services.capture_policy import (
    current_capture_policy,
    enforce_capture_policy,
)


class CapturePolicyTests(unittest.TestCase):
    def _build_request(self) -> Request:
        scope = {"type": "http", "headers": [], "client": ("127.0.0.1", 8765)}
        return Request(scope)

    @patch("backend.app.services.capture_policy.get_settings_snapshot", return_value={})
    def test_metadata_mode_allows_local_dev_without_safe_use(self, _mock_settings):
        with patch.dict(
            os.environ,
            {
                "NETBOT_CAPTURE_MODE": "metadata",
                "NETBOT_SAFE_USE_ACCEPTED": "0",
                "NETBOT_ALLOW_FULL_CAPTURE": "0",
            },
            clear=False,
        ):
            policy = enforce_capture_policy({"capture_mode": "metadata"})

        self.assertEqual(policy.mode, "metadata")
        self.assertFalse(policy.payload_capture_enabled)

    @patch("backend.app.services.capture_policy.get_settings_snapshot", return_value={})
    def test_full_mode_requires_safe_use(self, _mock_settings):
        with patch.dict(
            os.environ,
            {"NETBOT_ALLOW_FULL_CAPTURE": "1", "NETBOT_SAFE_USE_ACCEPTED": "0"},
            clear=False,
        ):
            with self.assertRaises(HTTPException) as ctx:
                enforce_capture_policy({"capture_mode": "full"})

        self.assertEqual(ctx.exception.status_code, 451)

    @patch("backend.app.services.capture_policy.get_settings_snapshot", return_value={})
    def test_full_mode_requires_allow_full_capture(self, _mock_settings):
        with patch.dict(
            os.environ,
            {"NETBOT_ALLOW_FULL_CAPTURE": "0", "NETBOT_SAFE_USE_ACCEPTED": "1"},
            clear=False,
        ):
            with self.assertRaises(HTTPException) as ctx:
                enforce_capture_policy({"capture_mode": "full"})

        self.assertEqual(ctx.exception.status_code, 403)

    @patch("backend.app.services.capture_policy.get_settings_snapshot", return_value={})
    def test_full_mode_accepts_explicit_authorization(self, _mock_settings):
        with patch.dict(
            os.environ,
            {
                "NETBOT_ALLOW_FULL_CAPTURE": "1",
                "NETBOT_SAFE_USE_ACCEPTED": "1",
                "NETBOT_PAYLOAD_CAPTURE": "1",
            },
            clear=False,
        ):
            policy = enforce_capture_policy({"capture_mode": "full"})

        self.assertEqual(policy.mode, "full")
        self.assertTrue(policy.payload_capture_enabled)

    @patch("backend.app.services.capture_policy.get_settings_snapshot", return_value={})
    def test_forensic_mode_requires_duration_or_explicit_confirmation(
        self, _mock_settings
    ):
        with patch.dict(
            os.environ,
            {"NETBOT_ALLOW_FULL_CAPTURE": "1", "NETBOT_SAFE_USE_ACCEPTED": "1"},
            clear=False,
        ):
            with self.assertRaises(HTTPException) as ctx:
                enforce_capture_policy({"capture_mode": "forensic"})
            policy = enforce_capture_policy(
                {"capture_mode": "forensic", "forensic_duration_minutes": 15}
            )

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(policy.mode, "forensic")
        self.assertEqual(policy.forensic_duration_minutes, 15)

    @patch(
        "backend.app.services.capture_policy.get_settings_snapshot",
        return_value={
            "capture_mode": "full",
            "allow_full_capture": True,
            "safe_use_policy_accepted": True,
        },
    )
    def test_settings_can_supply_capture_policy(self, _mock_settings):
        policy = current_capture_policy({})

        self.assertEqual(policy.mode, "full")
        self.assertTrue(policy.allow_full_capture)

    @patch("backend.app.services.capture_policy.get_settings_snapshot", return_value={})
    def test_raw_pcap_export_rejects_metadata_mode(self, _mock_settings):
        with patch.dict(
            os.environ,
            {
                "NETBOT_CAPTURE_MODE": "metadata",
                "NETBOT_ALLOW_FULL_CAPTURE": "0",
                "NETBOT_SAFE_USE_ACCEPTED": "0",
            },
            clear=False,
        ):
            with self.assertRaises(HTTPException) as ctx:
                main.api_raw_pcap_download(
                    "capture.pcap", self._build_request(), None, None
                )

        self.assertEqual(ctx.exception.status_code, 403)

    @patch("backend.app.services.capture_policy.get_settings_snapshot", return_value={})
    def test_raw_pcap_export_allows_full_mode(self, _mock_settings):
        with tempfile.TemporaryDirectory() as td:
            artifact = Path(td) / "capture.pcap"
            artifact.write_bytes(b"pcap bytes")
            with (
                patch.object(main, "LOG_DIR", Path(td)),
                patch.dict(
                    os.environ,
                    {
                        "NETBOT_CAPTURE_MODE": "full",
                        "NETBOT_ALLOW_FULL_CAPTURE": "1",
                        "NETBOT_SAFE_USE_ACCEPTED": "1",
                    },
                    clear=False,
                ),
            ):
                response = main.api_raw_pcap_download(
                    "capture.pcap", self._build_request(), None, None
                )

        self.assertEqual(response.filename, "capture.pcap")
        self.assertEqual(
            response.headers["X-NetBot-Warning"], "Raw PCAP may contain sensitive data"
        )

    @patch(
        "backend.app.services.capture_policy.get_settings_snapshot",
        return_value={"forensic_confirmed": True},
    )
    def test_raw_pcap_export_allows_forensic_mode_with_explicit_confirmation(
        self, _mock_settings
    ):
        with tempfile.TemporaryDirectory() as td:
            artifact = Path(td) / "capture.pcapng"
            artifact.write_bytes(b"pcapng bytes")
            with (
                patch.object(main, "LOG_DIR", Path(td)),
                patch.dict(
                    os.environ,
                    {
                        "NETBOT_CAPTURE_MODE": "forensic",
                        "NETBOT_ALLOW_FULL_CAPTURE": "1",
                        "NETBOT_SAFE_USE_ACCEPTED": "1",
                    },
                    clear=False,
                ),
            ):
                response = main.api_raw_pcap_download(
                    "capture.pcapng", self._build_request(), None, None
                )

        self.assertEqual(response.filename, "capture.pcapng")


if __name__ == "__main__":
    unittest.main()
