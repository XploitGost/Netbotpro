from __future__ import annotations

import socket
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from core.offline_analyzer import PacketLayers, analyze_pcap_file


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
    def test_windows_offline_reader_does_not_require_npcap_and_redacts_http_secrets(
        self,
    ):
        dns = (
            struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            + b"\x07example\x03com\x00"
            + struct.pack("!HH", 1, 1)
        )
        http = (
            b"GET /account?token=raw-secret HTTP/1.1\r\n"
            b"Host: example.com\r\nAuthorization: Bearer raw-secret\r\n\r\n"
        )

        def frame(src, dst, proto, transport):
            ip = struct.pack(
                "!BBHHHBBH4s4s",
                0x45,
                0,
                20 + len(transport),
                1,
                0,
                64,
                proto,
                0,
                socket.inet_aton(src),
                socket.inet_aton(dst),
            )
            return bytes.fromhex("00112233445566778899aabb0800") + ip + transport

        udp = struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns
        tcp = struct.pack("!HHLLBBHHH", 51000, 80, 1, 1, 0x50, 0x18, 8192, 0, 0) + http
        frames = [
            frame("10.0.0.5", "8.8.8.8", 17, udp),
            frame("10.0.0.5", "93.184.216.34", 6, tcp),
        ]

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "safe.pcap"
            with path.open("wb") as handle:
                handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
                now = int(time.time())
                for item in frames:
                    handle.write(struct.pack("<IIII", now, 0, len(item), len(item)))
                    handle.write(item)
            with patch("core.offline_analyzer.platform.system", return_value="Windows"):
                result = analyze_pcap_file(str(path))

        self.assertEqual(result["summary"]["total_packets"], 2)
        self.assertEqual(
            {flow["app_protocol"] for flow in result["flows"]}, {"DNS", "HTTP"}
        )
        self.assertNotIn("raw-secret", str(result))

    def test_offline_analysis_reports_attacks_in_summary(self):
        packets = [object(), object()]
        fake_layers = PacketLayers(
            Ether=object(),
            IP=object(),
            TCP=object(),
            UDP=object(),
            ICMP=object(),
            DNS=object(),
            DNSQR=object(),
        )
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

        with patch("core.offline_analyzer._read_pcap", return_value=packets), patch(
            "core.offline_analyzer._load_offline_settings",
            return_value={"ids_ml_threshold": 0.25, "auto_block": True},
        ), patch(
            "core.offline_analyzer._build_offline_pipeline",
            return_value=_FakePipeline(),
        ), patch(
            "core.offline_analyzer._packet_layers",
            return_value=fake_layers,
        ), patch(
            "core.offline_analyzer._build_meta",
            side_effect=lambda pkt, builder, index: {
                "id": f"pcap-pkt-{index + 1}",
                **metas[index],
            },
        ):
            result = analyze_pcap_file("dummy.pcap")

        self.assertTrue(result["summary"]["suspicious"])
        self.assertEqual(result["summary"]["total_packets"], 2)
        self.assertEqual(result["summary"]["total_alerts"], 1)
        self.assertEqual(result["summary"]["attack_types"], 1)
        self.assertEqual(
            result["top_attack_types"][0]["attack_type"], "Suspicious TLS Burst"
        )
        self.assertEqual(result["alerts"][0]["packet_id"], "pcap-pkt-1")
        self.assertIn("flow_summary", result)
        self.assertIn("top_conversations", result)
        self.assertIn("top_risky_flows", result)
        self.assertIn("protocol_summary", result)
        self.assertIn("risk_distribution", result)


if __name__ == "__main__":
    unittest.main()
