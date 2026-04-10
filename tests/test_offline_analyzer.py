from __future__ import annotations

import unittest
from unittest.mock import patch

from core.offline_analyzer import analyze_pcap_file


class _FakePipeline:
    def analyze(self, meta):
        if meta.get("dst") == "8.8.8.8":
            return [
                {
                    "ts": meta.get("ts"),
                    "src": meta.get("src"),
                    "dst": meta.get("dst"),
                    "proto": meta.get("proto"),
                    "attack_type": "Suspicious TLS Burst",
                    "severity": "HIGH",
                    "engine": "SIG",
                    "score": 0.91,
                    "detail": "synthetic alert",
                }
            ]
        return []


class OfflineAnalyzerTests(unittest.TestCase):
    def test_offline_analysis_reports_attacks_in_summary(self):
        packets = [object(), object()]
        metas = [
            {
                "src": "192.168.1.5",
                "dst": "8.8.8.8",
                "remote_ip": "8.8.8.8",
                "proto": "TCP",
                "dport": 443,
                "country": "US",
                "ts": "12:00:01",
            },
            {
                "src": "192.168.1.5",
                "dst": "1.1.1.1",
                "remote_ip": "1.1.1.1",
                "proto": "UDP",
                "dport": 53,
                "country": "AU",
                "ts": "12:00:05",
            },
        ]

        with patch("core.offline_analyzer.rdpcap", return_value=packets), patch(
            "core.offline_analyzer.get_settings_snapshot",
            return_value={"ids_ml_threshold": 0.25, "auto_block": True},
        ), patch(
            "core.offline_analyzer._build_offline_pipeline",
            return_value=_FakePipeline(),
        ), patch(
            "core.offline_analyzer._build_meta",
            side_effect=lambda pkt, builder, index: {"id": f"pcap-pkt-{index + 1}", **metas[index]},
        ):
            result = analyze_pcap_file("dummy.pcap")

        self.assertTrue(result["summary"]["suspicious"])
        self.assertEqual(result["summary"]["total_packets"], 2)
        self.assertEqual(result["summary"]["total_alerts"], 1)
        self.assertEqual(result["summary"]["attack_types"], 1)
        self.assertEqual(result["top_attack_types"][0]["attack_type"], "Suspicious TLS Burst")
        self.assertEqual(result["alerts"][0]["packet_id"], "pcap-pkt-1")


if __name__ == "__main__":
    unittest.main()
