import unittest
from unittest.mock import patch

from backend.app import main
from backend.app.schemas.models import StatusResponse


class ApiStatusTests(unittest.TestCase):
    def test_status_payload_excludes_project_root_and_matches_schema(self):
        expected_state = {"running": False, "iface": "default", "packet_count": 0}
        expected_observability = {"event_bus": {"subscribers": 0}}

        with (
            patch.object(main.sniffer_service, "get_state", return_value=expected_state),
            patch.object(main, "_observability_snapshot", return_value=expected_observability),
            patch.object(main, "is_local_token_enabled", return_value=False),
        ):
            payload = main.api_status(None)

        parsed = StatusResponse.model_validate(payload)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["sniffer"], expected_state)
        self.assertEqual(payload["observability"], expected_observability)
        self.assertFalse(payload["local_token_required"])
        self.assertNotIn("project_root", payload)
        self.assertNotIn("capture_preflight", payload)
        self.assertFalse(parsed.local_token_required)


if __name__ == "__main__":
    unittest.main()
