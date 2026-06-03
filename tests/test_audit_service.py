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
                    detail={"path": "report.html", "capture_mode": "full", "token": "secret"},
                )

            row = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])

        self.assertEqual(row["event_type"], "export_downloaded")
        self.assertEqual(row["client_ip"], "10.0.0.5")
        self.assertEqual(row["capture_mode"], "full")
        self.assertEqual(row["detail"]["token"], "[REDACTED]")


if __name__ == "__main__":
    unittest.main()
