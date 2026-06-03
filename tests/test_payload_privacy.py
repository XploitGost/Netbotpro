import unittest

from core.netbotpro_logging.privacy import alert_rows_to_df, packet_rows_to_df
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

    def test_export_dataframes_redact_packet_and_alert_text(self):
        packets = packet_rows_to_df(
            [
                {
                    "summary": "GET /login?token=secret HTTP/1.1",
                    "l7": "HTTP POST /?password=hunter2",
                }
            ]
        )
        alerts = alert_rows_to_df([{"detail": "Authorization: Bearer secret-token", "attack": "Cleartext Auth"}])

        packet_text = " ".join(str(value) for value in packets.iloc[0].to_dict().values())
        alert_text = " ".join(str(value) for value in alerts.iloc[0].to_dict().values())

        self.assertNotIn("token=secret", packet_text)
        self.assertNotIn("password=hunter2", packet_text)
        self.assertNotIn("secret-token", alert_text)
        self.assertIn("[REDACTED]", f"{packet_text} {alert_text}")


if __name__ == "__main__":
    unittest.main()
