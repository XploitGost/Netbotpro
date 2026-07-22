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

    def test_health_exposes_profile_without_secrets(self):
        with patch.dict(
            main.os.environ,
            {"NETBOT_PROFILE": "desktop", "NETBOT_TRUSTED_TOKENS": "secret-token"},
            clear=False,
        ):
            payload = main.api_health()

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["profile"], "desktop")
        self.assertNotIn("secret-token", str(payload))

    def test_readiness_reports_not_ready_reasons_without_secrets(self):
        with (
            patch.object(
                main,
                "_observability_snapshot",
                return_value={
                    "persistence": {"health": "critical", "last_error": "RuntimeError"},
                    "event_aggregator": {"health": "healthy"},
                    "live_ring_buffer": {"health": "healthy"},
                    "incidents": {"health": "healthy"},
                    "service_attribution": {"health": "critical", "registry_size": 0},
                },
            ),
            patch.object(main.sniffer_service, "get_state", return_value={}),
            patch.object(main.flow_service, "summary", return_value={}),
            patch.dict(
                main.os.environ,
                {"NETBOT_TRUSTED_TOKENS": "ready-secret"},
                clear=False,
            ),
        ):
            payload = main.api_ready()

        self.assertEqual(payload["status"], "not_ready")
        self.assertIn("service_attribution:registry_missing", payload["reasons"])
        self.assertNotIn("ready-secret", str(payload))


if __name__ == "__main__":
    unittest.main()
