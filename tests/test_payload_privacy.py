import unittest

from core.netbotpro_sniffer_core.layer7 import redact_http_path, redact_sensitive_text, safe_bytes_preview


class PayloadPrivacyTests(unittest.TestCase):
    def test_payload_preview_is_off_by_default(self):
        payload = b"GET / HTTP/1.1\r\nAuthorization: Bearer secret-token\r\n\r\n"

        preview = safe_bytes_preview(payload)

        self.assertEqual(preview["payload_len"], len(payload))
        self.assertEqual(preview["payload_hex"], "")
        self.assertEqual(preview["payload_ascii"], "")

    def test_payload_preview_redacts_sensitive_headers_when_enabled(self):
        payload = b"GET / HTTP/1.1\r\nAuthorization: Bearer secret-token\r\nCookie: sid=123\r\n\r\n"

        preview = safe_bytes_preview(payload, max_len=128, enabled=True)

        self.assertIn("[REDACTED]", preview["payload_ascii"])
        self.assertNotIn("secret-token", preview["payload_ascii"])
        self.assertNotIn("sid=123", preview["payload_ascii"])

    def test_redacts_basic_bearer_and_sensitive_query_values(self):
        text = "Authorization: Basic abc123\nGET /?token=secret&ok=1 HTTP/1.1"

        redacted = redact_sensitive_text(text)

        self.assertNotIn("abc123", redacted)
        self.assertNotIn("token=secret", redacted)
        self.assertEqual(redact_http_path("/login?access_token=secret&x=1"), "/login?access_token=[REDACTED]&x=1")


if __name__ == "__main__":
    unittest.main()
