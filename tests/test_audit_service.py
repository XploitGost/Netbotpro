import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app.services import audit_service


class AuditServiceTests(unittest.TestCase):
    def test_audit_event_writes_standard_fields_and_redacts_tokens(self):
        with tempfile.TemporaryDirectory() as td:
            audit_path = Path(td) / "audit.jsonl"
            with patch.object(audit_service, "_AUDIT_PATH", audit_path):
                audit_service.audit_event(
                    "export_downloaded",
                    actor="10.0.0.5",
                    detail={
                        "path": "report.html",
                        "capture_mode": "full",
                        "token": "secret",
                    },
                )

            row = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])

        self.assertEqual(row["event_type"], "export_downloaded")
        self.assertEqual(row["client_ip"], "10.0.0.5")
        self.assertEqual(row["capture_mode"], "full")
        self.assertEqual(row["detail"]["token"], "[REDACTED]")

    def test_audit_event_redacts_sensitive_text_fields(self):
        with tempfile.TemporaryDirectory() as td:
            audit_path = Path(td) / "audit.jsonl"
            with patch.object(audit_service, "_AUDIT_PATH", audit_path):
                audit_service.audit_event(
                    "settings_changed",
                    actor="operator",
                    detail={
                        "capture_mode": "full",
                        "reason": "Authorization: Bearer secret-token",
                        "target": "/api?api_key=secret-key",
                        "nested": {"message": "Cookie: sid=session-secret"},
                    },
                )

            row = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])

        payload = json.dumps(row, ensure_ascii=False)
        self.assertNotIn("secret-token", payload)
        self.assertNotIn("secret-key", payload)
        self.assertNotIn("session-secret", payload)
        self.assertIn("[REDACTED]", payload)


if __name__ == "__main__":
    unittest.main()
