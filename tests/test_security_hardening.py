import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from backend.app.security import check_local_token, ensure_within_directory, is_allowed_websocket_origin
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

    def test_websocket_origin_check_accepts_local_frontend_only(self):
        self.assertTrue(is_allowed_websocket_origin("http://127.0.0.1:5173"))
        self.assertTrue(is_allowed_websocket_origin("http://localhost:5173/"))
        self.assertFalse(is_allowed_websocket_origin("https://evil.example"))


if __name__ == "__main__":
    unittest.main()
