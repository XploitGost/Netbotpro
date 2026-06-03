import unittest

from agent.agent_runner import sanitize_agent_log_message


class AgentLoggingTests(unittest.TestCase):
    def test_agent_log_sanitizer_removes_raw_token_from_exception_text(self):
        token = "agent-token-should-not-leak"
        message = RuntimeError(f"POST failed with X-NetBot-Agent-Token={token}")

        sanitized = sanitize_agent_log_message(message, token)

        self.assertNotIn(token, sanitized)
        self.assertIn("[REDACTED]", sanitized)

    def test_agent_log_sanitizer_masks_common_secret_shapes(self):
        token = "plain-agent-token"
        message = (
            "Authorization: Bearer bearer-secret; "
            "api_key=api-secret; "
            f"token={token}"
        )

        sanitized = sanitize_agent_log_message(message, token)

        self.assertNotIn("bearer-secret", sanitized)
        self.assertNotIn("api-secret", sanitized)
        self.assertNotIn(token, sanitized)


if __name__ == "__main__":
    unittest.main()
