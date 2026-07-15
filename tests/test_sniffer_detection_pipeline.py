import unittest
from unittest.mock import patch

from backend.app.services.sniffer_detection_pipeline import SnifferDetectionPipeline


class _RuleEngine:
    def analyze(self, packet):
        return {
            "attack_type": "Scan",
            "severity": "high",
            "score": 0.95,
            "detail": f"match:{packet['src']}",
        }


class _NoopEngine:
    def analyze(self, *args, **kwargs):
        return None

    def analyze_packet(self, *args, **kwargs):
        return None


class _NoopScorer:
    def enrich_alert(self, packet, alert, sig_engine=None):
        return None


class _NoopIncidents:
    def enrich_alert(self, packet, alert):
        return None


class SnifferDetectionPipelineTests(unittest.TestCase):
    def test_encrypted_data_packets_without_sni_do_not_create_false_beacon_alerts(self):
        pipeline = SnifferDetectionPipeline(settings_provider=lambda: {})
        packet = {
            "src": "10.0.0.5",
            "dst": "142.251.156.4",
            "remote_ip": "142.251.156.4",
            "dport": 443,
            "proto": "UDP",
            "app_protocol": "HTTPS",
            "direction": "OUTGOING",
            "org": "Google LLC",
        }
        alerts = []
        for _ in range(10):
            alerts.extend(pipeline._detect_application_alerts(dict(packet)))
        self.assertNotIn(
            "TLS Without SNI / Beacon Pattern",
            {item.get("attack_type") for item in alerts},
        )

    def test_repeated_client_hello_without_sni_can_still_alert(self):
        pipeline = SnifferDetectionPipeline(settings_provider=lambda: {})
        packet = {
            "src": "10.0.0.5",
            "dst": "8.8.8.8",
            "remote_ip": "8.8.8.8",
            "dport": 443,
            "proto": "TCP",
            "app_protocol": "TLS",
            "direction": "OUTGOING",
            "protocol_handshake": "TLS ClientHello",
        }
        alerts = []
        for _ in range(4):
            alerts.extend(pipeline._detect_application_alerts(dict(packet)))
        self.assertIn(
            "TLS Without SNI / Beacon Pattern",
            {item.get("attack_type") for item in alerts},
        )

    def test_pipeline_enriches_packets_with_app_protocol_metadata(self):
        pipeline = SnifferDetectionPipeline(
            settings_provider=lambda: {
                "auto_block": False,
                "ids_signature_enabled": False,
                "ids_ml_enabled": False,
            },
            ids_sig=_NoopEngine(),
            ids_ml=_NoopEngine(),
            rule_engine=_NoopEngine(),
            scorer=_NoopScorer(),
            incidents=_NoopIncidents(),
        )
        packet = {
            "src": "10.0.0.4",
            "dst": "8.8.8.8",
            "proto": "UDP",
            "dport": 53,
            "dns_qname": "api.example.com",
            "ts": "now",
        }

        alerts = pipeline.analyze(packet)

        self.assertEqual(alerts, [])
        self.assertEqual(packet["app_protocol"], "DNS")
        self.assertEqual(packet["app_category"], "dns")
        self.assertEqual(packet["protocol_handshake"], "DNS question")

    def test_pipeline_marks_http_on_unusual_port(self):
        pipeline = SnifferDetectionPipeline(
            settings_provider=lambda: {
                "auto_block": False,
                "ids_signature_enabled": False,
                "ids_ml_enabled": False,
            },
            ids_sig=_NoopEngine(),
            ids_ml=_NoopEngine(),
            rule_engine=_NoopEngine(),
            scorer=_NoopScorer(),
            incidents=_NoopIncidents(),
        )
        packet = {
            "src": "10.0.0.4",
            "dst": "93.184.216.34",
            "remote_ip": "93.184.216.34",
            "proto": "TCP",
            "dport": 8088,
            "http_method": "GET",
            "http_host": "example.com",
            "http_path": "/status",
            "ts": "now",
        }

        alerts = pipeline.analyze(packet)

        self.assertEqual(alerts, [])
        self.assertEqual(packet["app_protocol"], "HTTP")
        self.assertTrue(packet["protocol_unusual_port"])
        self.assertIn("unusual port 8088", packet["protocol_basis"])

    def test_pipeline_detects_repeated_dns_tunneling_pattern(self):
        pipeline = SnifferDetectionPipeline(
            settings_provider=lambda: {
                "auto_block": False,
                "ids_signature_enabled": False,
                "ids_ml_enabled": False,
            },
            ids_sig=_NoopEngine(),
            ids_ml=_NoopEngine(),
            rule_engine=_NoopEngine(),
            scorer=_NoopScorer(),
            incidents=_NoopIncidents(),
        )
        packet = {
            "src": "10.0.0.4",
            "dst": "8.8.8.8",
            "remote_ip": "8.8.8.8",
            "proto": "UDP",
            "dport": 53,
            "dns_qname": "ajd93jd92jd92jd92jd92jd92jd92jd92jd92jd92jd.example.com",
            "dns_qtype": 16,
            "ts": "now",
        }

        first = pipeline.analyze(dict(packet))
        second = pipeline.analyze(dict(packet))
        third = pipeline.analyze(dict(packet))

        self.assertEqual(first, [])
        self.assertEqual(second, [])
        self.assertEqual(len(third), 1)
        self.assertEqual(third[0]["attack_type"], "DNS Tunneling / Exfil Pattern")
        self.assertEqual(third[0]["app_protocol"], "DNS")

    def test_pipeline_detects_cleartext_http_auth(self):
        pipeline = SnifferDetectionPipeline(
            settings_provider=lambda: {
                "auto_block": False,
                "ids_signature_enabled": False,
                "ids_ml_enabled": False,
            },
            ids_sig=_NoopEngine(),
            ids_ml=_NoopEngine(),
            rule_engine=_NoopEngine(),
            scorer=_NoopScorer(),
            incidents=_NoopIncidents(),
        )

        alerts = pipeline.analyze(
            {
                "src": "10.0.0.4",
                "dst": "93.184.216.34",
                "remote_ip": "93.184.216.34",
                "proto": "TCP",
                "dport": 80,
                "http_method": "POST",
                "http_host": "example.com",
                "http_path": "/login",
                "ts": "now",
            }
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["attack_type"], "Cleartext Auth Over HTTP")
        self.assertEqual(alerts[0]["app_protocol"], "HTTP")
        self.assertFalse(alerts[0]["protocol_unusual_port"])
        self.assertEqual(alerts[0]["protocol_handshake"], "HTTP request")

    @patch(
        "backend.app.services.sniffer_detection_pipeline.block_ip", return_value=True
    )
    def test_auto_block_uses_cooldown_and_skips_duplicate_blocks(self, mock_block_ip):
        pipeline = SnifferDetectionPipeline(
            settings_provider=lambda: {
                "auto_block": True,
                "ids_signature_enabled": False,
                "ids_ml_enabled": False,
            },
            ids_sig=_NoopEngine(),
            ids_ml=_NoopEngine(),
            rule_engine=_RuleEngine(),
            scorer=_NoopScorer(),
            incidents=_NoopIncidents(),
        )
        packet = {"src": "8.8.8.8", "dst": "10.0.0.2", "proto": "TCP", "ts": "now"}

        first = pipeline.analyze(packet)
        second = pipeline.analyze(packet)

        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertEqual(mock_block_ip.call_count, 1)
        stats = pipeline.stats()
        self.assertEqual(stats["blocked_total"], 1)
        self.assertEqual(stats["cooldown_skips"], 1)

    @patch(
        "backend.app.services.sniffer_detection_pipeline.block_ip", return_value=True
    )
    def test_auto_block_skips_private_source_ips(self, mock_block_ip):
        pipeline = SnifferDetectionPipeline(
            settings_provider=lambda: {
                "auto_block": True,
                "ids_signature_enabled": False,
                "ids_ml_enabled": False,
            },
            ids_sig=_NoopEngine(),
            ids_ml=_NoopEngine(),
            rule_engine=_RuleEngine(),
            scorer=_NoopScorer(),
            incidents=_NoopIncidents(),
        )

        pipeline.analyze(
            {"src": "192.168.1.20", "dst": "10.0.0.2", "proto": "TCP", "ts": "now"}
        )

        self.assertEqual(mock_block_ip.call_count, 0)
        self.assertEqual(pipeline.stats()["private_ip_skips"], 1)

    @patch(
        "backend.app.services.sniffer_detection_pipeline.block_ip", return_value=True
    )
    def test_auto_block_skips_cgnat_source_ips(self, mock_block_ip):
        pipeline = SnifferDetectionPipeline(
            settings_provider=lambda: {
                "auto_block": True,
                "ids_signature_enabled": False,
                "ids_ml_enabled": False,
            },
            ids_sig=_NoopEngine(),
            ids_ml=_NoopEngine(),
            rule_engine=_RuleEngine(),
            scorer=_NoopScorer(),
            incidents=_NoopIncidents(),
        )

        pipeline.analyze(
            {"src": "100.64.10.20", "dst": "10.0.0.2", "proto": "TCP", "ts": "now"}
        )

        self.assertEqual(mock_block_ip.call_count, 0)
        self.assertEqual(pipeline.stats()["private_ip_skips"], 1)


if __name__ == "__main__":
    unittest.main()
