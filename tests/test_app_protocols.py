import unittest

from backend.app.services.app_protocols import infer_app_protocol


class AppProtocolInferenceTests(unittest.TestCase):
    def test_http_request_on_unusual_port_is_identified(self):
        packet = {
            "proto": "TCP",
            "dport": 8088,
            "http_method": "GET",
            "http_host": "example.com",
            "http_path": "/status",
        }

        enriched = infer_app_protocol(packet)

        self.assertEqual(enriched["app_protocol"], "HTTP")
        self.assertEqual(enriched["app_category"], "web")
        self.assertEqual(enriched["app_confidence"], "high")
        self.assertTrue(enriched["protocol_unusual_port"])
        self.assertIn("HTTP request", enriched["protocol_handshake"])
        self.assertIn("unusual port 8088", enriched["protocol_basis"])

    def test_tls_on_non_standard_port_is_marked_unusual(self):
        packet = {
            "proto": "TCP",
            "dport": 10443,
            "tls_version": "TLS1.3",
            "tls_sni": "api.example.com",
            "ja3": "abcdef1234567890",
        }

        enriched = infer_app_protocol(packet)

        self.assertEqual(enriched["app_protocol"], "TLS")
        self.assertEqual(enriched["app_category"], "encrypted")
        self.assertEqual(enriched["app_confidence"], "high")
        self.assertTrue(enriched["protocol_unusual_port"])
        self.assertEqual(enriched["protocol_handshake"], "TLS ClientHello")

    def test_quic_candidate_is_detected_from_udp_payload_shape(self):
        packet = {
            "proto": "UDP",
            "dport": 443,
            "payload_hex": "c3 00 00 00 01 08 45 00 00 00",
        }

        enriched = infer_app_protocol(packet)

        self.assertEqual(enriched["app_protocol"], "QUIC")
        self.assertEqual(enriched["app_category"], "web")
        self.assertEqual(enriched["app_confidence"], "high")
        self.assertIn("QUIC", enriched["protocol_handshake"])

    def test_nat_t_candidate_uses_non_esp_marker(self):
        packet = {
            "proto": "UDP",
            "dport": 4500,
            "payload_hex": "00 00 00 00 21 22 23 24 25 26",
        }

        enriched = infer_app_protocol(packet)

        self.assertEqual(enriched["app_protocol"], "IPsec NAT-T")
        self.assertEqual(enriched["app_category"], "vpn")
        self.assertEqual(enriched["app_confidence"], "high")
        self.assertIn("Non-ESP marker", enriched["protocol_basis"])
        self.assertTrue(enriched["payload_binary_like"])


if __name__ == "__main__":
    unittest.main()
