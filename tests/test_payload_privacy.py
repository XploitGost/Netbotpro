import unittest

from backend.app.services.redaction import redact_http_path as service_redact_http_path
from backend.app.services.redaction import (
    redact_sensitive_data,
    redact_sensitive_text as service_redact_sensitive_text,
)
from core.netbotpro_logging.privacy import alert_rows_to_df, packet_rows_to_df
from core.netbotpro_sniffer_core.layer7 import (
    redact_http_path,
    redact_sensitive_text,
    safe_bytes_preview,
)
from core.privacy_redaction import redact_http_path as core_redact_http_path
from core.privacy_redaction import redact_sensitive_text as core_redact_sensitive_text


class PayloadPrivacyTests(unittest.TestCase):
    def test_recursive_redaction_masks_sensitive_mapping_values(self):
        redacted = redact_sensitive_data(
            {
                "authorization": "Bearer real-secret",
                "nested": {"cookie": "session=real-secret"},
                "items": ["password=real-secret"],
            }
        )

        self.assertNotIn("real-secret", str(redacted))
        self.assertEqual(redacted["authorization"], "[REDACTED]")

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
        self.assertEqual(
            redact_http_path("/login?access_token=secret&x=1"),
            "/login?access_token=[REDACTED]&x=1",
        )

    def test_central_redaction_masks_common_credential_shapes(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        text = "\n".join(
            [
                "Authorization: Bearer bearer-secret",
                "Proxy-Authorization: Basic basic-secret",
                "Cookie: sid=cookie-secret",
                "password=hunter2",
                "token=query-secret",
                "api_key=api-secret",
                "secret=shared-secret",
                "session=session-secret",
                jwt,
            ]
        )

        redacted = service_redact_sensitive_text(text)
        core_redacted = core_redact_sensitive_text(text)

        for secret in [
            "bearer-secret",
            "basic-secret",
            "cookie-secret",
            "hunter2",
            "query-secret",
            "api-secret",
            "shared-secret",
            "session-secret",
            jwt,
        ]:
            self.assertNotIn(secret, redacted)
        self.assertIn("[REDACTED]", redacted)
        self.assertIn("[REDACTED_JWT]", redacted)
        self.assertEqual(redacted, core_redacted)

    def test_backend_and_core_redact_http_path_match(self):
        path = "/login?access_token=secret-token&session=session-secret&ok=1"

        self.assertEqual(service_redact_http_path(path), core_redact_http_path(path))
        self.assertEqual(
            service_redact_http_path(path),
            "/login?access_token=[REDACTED]&session=[REDACTED]&ok=1",
        )

    def test_export_dataframes_redact_packet_and_alert_text(self):
        packets = packet_rows_to_df(
            [
                {
                    "summary": "GET /login?token=secret HTTP/1.1",
                    "l7": "HTTP POST /?password=hunter2",
                }
            ]
        )
        alerts = alert_rows_to_df(
            [
                {
                    "detail": "Authorization: Bearer secret-token",
                    "attack": "Cleartext Auth",
                }
            ]
        )

        packet_text = " ".join(
            str(value) for value in packets.iloc[0].to_dict().values()
        )
        alert_text = " ".join(str(value) for value in alerts.iloc[0].to_dict().values())

        self.assertNotIn("token=secret", packet_text)
        self.assertNotIn("password=hunter2", packet_text)
        self.assertNotIn("secret-token", alert_text)
        self.assertIn("[REDACTED]", f"{packet_text} {alert_text}")


if __name__ == "__main__":
    unittest.main()
