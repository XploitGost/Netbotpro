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
    def analyze_packet(self, *args, **kwargs):
        return None


class _NoopScorer:
    def enrich_alert(self, packet, alert, sig_engine=None):
        return None


class _NoopIncidents:
    def enrich_alert(self, packet, alert):
        return None


class SnifferDetectionPipelineTests(unittest.TestCase):
    @patch("backend.app.services.sniffer_detection_pipeline.block_ip", return_value=True)
    def test_auto_block_uses_cooldown_and_skips_duplicate_blocks(self, mock_block_ip):
        pipeline = SnifferDetectionPipeline(
            settings_provider=lambda: {"auto_block": True, "ids_signature_enabled": False, "ids_ml_enabled": False},
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

    @patch("backend.app.services.sniffer_detection_pipeline.block_ip", return_value=True)
    def test_auto_block_skips_private_source_ips(self, mock_block_ip):
        pipeline = SnifferDetectionPipeline(
            settings_provider=lambda: {"auto_block": True, "ids_signature_enabled": False, "ids_ml_enabled": False},
            ids_sig=_NoopEngine(),
            ids_ml=_NoopEngine(),
            rule_engine=_RuleEngine(),
            scorer=_NoopScorer(),
            incidents=_NoopIncidents(),
        )

        pipeline.analyze({"src": "192.168.1.20", "dst": "10.0.0.2", "proto": "TCP", "ts": "now"})

        self.assertEqual(mock_block_ip.call_count, 0)
        self.assertEqual(pipeline.stats()["private_ip_skips"], 1)


if __name__ == "__main__":
    unittest.main()
