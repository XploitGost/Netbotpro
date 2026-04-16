import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from backend.app.services.export_service import ExportService
from backend.app.services.traceroute_service import TracerouteService


class ServiceHardeningTests(unittest.TestCase):
    def test_export_service_returns_safe_relative_filename(self):
        with tempfile.TemporaryDirectory() as td:
            def write_csv(path, packet_rows):
                Path(path).write_text("csv", encoding="utf-8")

            with (
                patch("backend.app.services.export_service.LOG_DIR", td),
                patch("backend.app.services.export_service.export_packets_csv", side_effect=write_csv),
            ):
                result = ExportService().export_session("csv", packet_rows=[], alert_rows=[], traceroute_rows=[])

            self.assertTrue(result["ok"])
            self.assertEqual(result["format"], "csv")
            self.assertEqual(Path(result["path"]).name, result["path"])
            self.assertFalse(Path(result["path"]).is_absolute())

    def test_traceroute_service_rejects_invalid_mode(self):
        service = TracerouteService()

        with self.assertRaises(HTTPException) as ctx:
            service.run({"target": "8.8.8.8", "mode": "shell"})

        self.assertEqual(ctx.exception.status_code, 400)

    def test_traceroute_service_clamps_numeric_bounds(self):
        service = TracerouteService()
        with patch("backend.app.services.traceroute_service.run_traceroute", return_value=[]):
            result = service.run(
                {
                    "target": "8.8.8.8",
                    "timeout": "99",
                    "max_hops": "0",
                    "queries": "99",
                    "port": "70000",
                }
            )

        self.assertEqual(result["timeout"], 10.0)
        self.assertEqual(result["max_hops"], 1)
        self.assertEqual(result["queries"], 5)
        self.assertEqual(result["port"], 65535)


if __name__ == "__main__":
    unittest.main()
