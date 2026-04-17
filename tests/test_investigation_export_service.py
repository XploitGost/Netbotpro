import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app.services.investigation_export_service import InvestigationExportService


class InvestigationExportServiceTests(unittest.TestCase):
    def test_export_report_returns_safe_relative_filename_and_sanitizes_runtime_paths(self):
        payload = {
            "kind": "packet",
            "id": "stream-4",
            "headline": "Inbound HTTP investigation",
            "summary_text": "Stream summary",
            "interpreted_summary": "Analyst-readable stream summary",
            "analyst_cards": [
                {"label": "Risk", "value": "Medium", "hint": "Suspicious auth failures"},
            ],
            "model": {
                "headline": "Inbound HTTP investigation",
                "summaryText": "Stream summary",
                "interpretedSummary": "Analyst-readable stream summary",
                "processRows": [
                    {"label": "Executable Path", "value": "C:/Users/Alice/AppData/Local/Temp/secret.exe"},
                ],
                "streamGroups": [
                    {
                        "title": "Stream Anomalies",
                        "items": [
                            {
                                "title": "Repeated failed auth-like exchanges",
                                "body": "Observed around C:/Sensitive/Runtime/cache.bin",
                            }
                        ],
                    }
                ],
                "riskExplanation": {
                    "narrative": "Review process execution from C:/Program Files/Netbotpro/netbot.exe",
                },
            },
        }

        with tempfile.TemporaryDirectory() as td:
            with patch("backend.app.services.investigation_export_service.LOG_DIR", td):
                result = InvestigationExportService().export_report(payload)

            self.assertTrue(result["ok"])
            self.assertEqual(result["format"], "html")
            self.assertEqual(Path(result["path"]).name, result["path"])
            self.assertFalse(Path(result["path"]).is_absolute())
            html = (Path(td) / result["path"]).read_text(encoding="utf-8")

        self.assertIn("secret.exe", html)
        self.assertNotIn("C:/Users/Alice", html)
        self.assertNotIn("C:/Sensitive/Runtime", html)
        self.assertNotIn("C:/Program Files/Netbotpro", html)
        self.assertIn("[redacted-path]/secret.exe", html)

    def test_export_report_handles_partial_model_fallback(self):
        payload = {
            "kind": "alert",
            "id": "anom-alert-1",
            "headline": "Partial stream alert",
            "model": {
                "headline": "Partial stream alert",
                "summaryText": "Fallback summary only",
                "streamGroups": [
                    {
                        "title": "Stream Notes",
                        "items": [
                            {"title": "Fallback / Reassembly note", "body": "Stream reconstruction is partial."},
                        ],
                    }
                ],
            },
        }

        with tempfile.TemporaryDirectory() as td:
            with patch("backend.app.services.investigation_export_service.LOG_DIR", td):
                result = InvestigationExportService().export_report(payload)
            html = (Path(td) / result["path"]).read_text(encoding="utf-8")

        self.assertIn("Partial stream alert", html)
        self.assertIn("Stream reconstruction is partial.", html)
        self.assertNotIn("Request / Response Clusters", html)


if __name__ == "__main__":
    unittest.main()
