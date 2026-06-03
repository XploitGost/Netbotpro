import json
import tempfile
import unittest
import uuid
from pathlib import Path

from agent.agent_identity import build_registration_payload, load_or_create_agent_id


class AgentIdentityTests(unittest.TestCase):
    def test_identity_file_is_created_and_reused(self):
        with tempfile.TemporaryDirectory() as td:
            identity_path = Path(td) / "agent-identity.json"

            first = load_or_create_agent_id(identity_path)
            second = load_or_create_agent_id(identity_path)

        self.assertEqual(first, second)
        self.assertEqual(str(uuid.UUID(first)), first)

    def test_configured_identity_is_validated_and_persisted(self):
        configured = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as td:
            identity_path = Path(td) / "agent-identity.json"

            result = load_or_create_agent_id(identity_path, configured)
            stored = json.loads(identity_path.read_text(encoding="utf-8"))

        self.assertEqual(result, configured)
        self.assertEqual(stored["agent_id"], configured)

    def test_registration_payload_contains_safe_capabilities(self):
        agent_id = str(uuid.uuid4())

        payload = build_registration_payload(agent_id, "prod-web-1")

        self.assertEqual(payload["agent_id"], agent_id)
        self.assertIn("health", payload["capabilities"])
        self.assertIn("alerts_summary", payload["capabilities"])
        self.assertNotIn("raw_pcap", payload["capabilities"])


if __name__ == "__main__":
    unittest.main()
