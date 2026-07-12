import unittest

from backend.app.services.service_attribution import attribute_service


class ServiceAttributionTests(unittest.TestCase):
    def test_googlevideo_sni_is_youtube_high_confidence(self):
        result = attribute_service(
            {
                "process_name": "chrome.exe",
                "tls_sni": "r1.googlevideo.com",
                "dport": 443,
            }
        )
        self.assertEqual(result["service_name"], "YouTube")
        self.assertEqual(result["service_confidence"], "high")

    def test_google_org_without_domain_is_conservative(self):
        result = attribute_service(
            {"process_name": "chrome.exe", "org": "Google LLC", "sport": 443}
        )
        self.assertEqual(result["service_name"], "Google Services")
        self.assertEqual(result["service_confidence"], "low")
        self.assertEqual(result["service_sources"], ["asn_org"])

    def test_unknown_encrypted_destination_is_not_invented(self):
        result = attribute_service({"process_name": "chrome.exe", "dport": 443})
        self.assertTrue(result["service_unknown"])
        self.assertEqual(result["service_name"], "Unknown Encrypted")

    def test_sensitive_domain_text_is_redacted(self):
        result = attribute_service(
            {"http_host": "example.test", "org": "token=raw-secret", "dport": 443}
        )
        self.assertNotIn("raw-secret", str(result))


if __name__ == "__main__":
    unittest.main()
