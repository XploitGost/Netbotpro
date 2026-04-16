import os
import tempfile
import unittest
from base64 import urlsafe_b64encode
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from backend.app.security import (
    WEBSOCKET_APP_PROTOCOL,
    allowed_origins,
    check_local_token,
    ensure_within_directory,
    extract_websocket_token,
    is_allowed_websocket_origin,
    is_loopback_host,
    validate_report_download_path,
)
from backend.app.services.report_service import ReportService


class SecurityHardeningTests(unittest.TestCase):
    def test_check_local_token_uses_expected_value(self):
        with patch.dict(os.environ, {"NETBOT_LOCAL_TOKEN": "super-secret"}, clear=False):
            self.assertTrue(check_local_token("super-secret"))
            self.assertFalse(check_local_token("wrong-token"))

    def test_ensure_within_directory_blocks_prefix_escape(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            sibling = base.parent / f"{base.name}-shadow" / "escape.txt"
            with self.assertRaises(HTTPException):
                ensure_within_directory(str(base), str(sibling))

    def test_report_service_returns_safe_relative_download_path(self):
        with tempfile.TemporaryDirectory() as td:
            report_path = Path(td) / "report_a.html"
            report_path.write_text("ok", encoding="utf-8")
            with patch("backend.app.services.report_service.LOG_DIR", td):
                items = ReportService().list_reports()

            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["name"], "report_a.html")
            self.assertEqual(items[0]["path"], "report_a.html")

    def test_report_service_filters_unsupported_and_symlinked_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "report_a.html").write_text("ok", encoding="utf-8")
            (root / "notes.txt").write_text("ignore", encoding="utf-8")
            try:
                (root / "report_link.html").symlink_to(root / "report_a.html")
            except OSError:
                pass
            with patch("backend.app.services.report_service.LOG_DIR", td):
                items = ReportService().list_reports()

            self.assertEqual([item["name"] for item in items], ["report_a.html"])

    def test_validate_report_download_path_rejects_unsafe_paths(self):
        with self.assertRaises(HTTPException):
            validate_report_download_path("../report.html")
        with self.assertRaises(HTTPException):
            validate_report_download_path("notes.txt")

    def test_websocket_origin_check_accepts_local_frontend_only(self):
        self.assertTrue(is_allowed_websocket_origin("http://127.0.0.1:5173"))
        self.assertTrue(is_allowed_websocket_origin("http://localhost:5173/"))
        self.assertFalse(is_allowed_websocket_origin("https://evil.example"))

    def test_allowed_origins_can_enable_desktop_runtime(self):
        with patch.dict(os.environ, {"NETBOT_ALLOWED_ORIGINS": "http://127.0.0.1:5173, null, file://"}, clear=False):
            self.assertIn("null", allowed_origins())
            self.assertTrue(is_allowed_websocket_origin("null"))

    def test_extract_websocket_token_accepts_subprotocol_auth(self):
        encoded = urlsafe_b64encode(b"desktop-secret").decode("ascii").rstrip("=")
        token, protocol = extract_websocket_token(f"{WEBSOCKET_APP_PROTOCOL}, netbot.auth.{encoded}", "")

        self.assertEqual(token, "desktop-secret")
        self.assertEqual(protocol, WEBSOCKET_APP_PROTOCOL)

    def test_extract_websocket_token_keeps_protocol_when_auth_order_changes(self):
        encoded = urlsafe_b64encode(b"desktop-secret").decode("ascii").rstrip("=")
        token, protocol = extract_websocket_token(f"netbot.auth.{encoded}, {WEBSOCKET_APP_PROTOCOL}", "")

        self.assertEqual(token, "desktop-secret")
        self.assertEqual(protocol, WEBSOCKET_APP_PROTOCOL)

    def test_loopback_helper_accepts_ipv4_mapped_ipv6(self):
        self.assertTrue(is_loopback_host("::ffff:127.0.0.1"))
        self.assertFalse(is_loopback_host("::ffff:10.0.0.8"))


if __name__ == "__main__":
    unittest.main()
