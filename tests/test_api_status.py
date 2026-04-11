import unittest
from unittest.mock import patch

import backend.app.main as main
from backend.app.schemas import StatusResponse


class ApiStatusTests(unittest.TestCase):
    def test_status_payload_excludes_project_root_and_matches_schema(self):
        expected_state = {
            "running": False,
            "iface": None,
            "packet_count": 0,
            "total_packets": 0,
            "total_alerts": 0,
            "observability": {},
        }
        expected_preflight = {
            "provider": "fake",
            "ready": True,
            "checks": [{"code": "interfaces_available", "ok": True}],
        }
        expected_observability = {"event_bus": {"subscribers": 0}}

        with (
            patch.object(main.sniffer_service, "get_state", return_value=expected_state),
            patch.object(main.sniffer_service, "capture_preflight", return_value=expected_preflight),
            patch.object(main, "_observability_snapshot", return_value=expected_observability),
            patch.object(main, "is_local_token_enabled", return_value=False),
        ):
            payload = main.api_status(None)

            StatusResponse.model_validate(payload)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["sniffer"], expected_state)
            self.assertEqual(payload["capture_preflight"], expected_preflight)
            self.assertEqual(payload["observability"], expected_observability)
            self.assertFalse(payload["local_token_required"])
            self.assertNotIn("project_root", payload)


if __name__ == "__main__":
    unittest.main()
