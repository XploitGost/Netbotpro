from __future__ import annotations

import unittest

from core.display_filter import DisplayFilterError, apply_display_filter, compile_display_filter
from core.expert_info import flow_expert_items, packet_expert_items
from core.packet_dissector import dissect_packet
from core.stream_reassembler import reconstruct_stream


class DeepPacketInspectionTests(unittest.TestCase):
    def packet(self, **overrides):
        packet = {
            "id": "pkt-1", "ts": "2026-06-08T09:00:00+00:00",
            "src": "10.0.0.5", "dst": "8.8.8.8",
            "src_mac": "aa:bb:cc:dd:ee:ff", "dst_mac": "11:22:33:44:55:66",
            "sport": 51000, "dport": 80, "proto": "TCP", "app_protocol": "HTTP",
            "flags": "S", "length": 128, "ttl": 64, "http_method": "GET",
            "http_host": "example.org", "http_path": "/login?token=raw-secret",
            "summary": "Authorization: Bearer raw-secret Cookie: session=raw-secret",
            "payload_ascii": "password=raw-secret",
            "payload_hex": "70617373776f72643d7261772d736563726574",
        }
        packet.update(overrides)
        return packet

    def test_tree_shape_layers_and_byte_ranges(self):
        result = dissect_packet(self.packet())
        self.assertEqual(result["protocol_stack"], ["Frame", "Ethernet", "IPv4", "TCP", "HTTP"])
        self.assertEqual(result["layers"][2]["fields"][1]["byte_range"], [26, 30])
        self.assertNotIn("raw-secret", str(result))

    def test_arp_ipv6_udp_icmp_and_unknown_shapes(self):
        arp = dissect_packet(self.packet(arp_operation=1, arp_sender_ip="10.0.0.5", arp_target_ip="10.0.0.1"))
        ipv6 = dissect_packet(self.packet(src="2001:db8::1", dst="2001:db8::2", proto="UDP", app_protocol="UNKNOWN"))
        icmp = dissect_packet(self.packet(proto="ICMP", app_protocol="ICMP", sport=None, dport=None))
        self.assertIn("ARP", arp["protocol_stack"])
        self.assertIn("IPv6", ipv6["protocol_stack"])
        self.assertIn("UDP", ipv6["protocol_stack"])
        self.assertIn("ICMP", icmp["protocol_stack"])

    def test_hex_metadata_hides_payload_and_full_redacts_ascii(self):
        self.assertEqual(dissect_packet(self.packet(), capture_mode="metadata")["hex"]["rows"], [])
        full = dissect_packet(self.packet(), capture_mode="full")
        self.assertTrue(full["hex"]["rows"])
        self.assertNotIn("raw-secret", str(full["hex"]))

    def test_display_filter_valid_invalid_and_operators(self):
        rows = [self.packet(risk_score=65), self.packet(id="pkt-2", src="1.1.1.1", dport=443, risk_score=10)]
        self.assertEqual(len(apply_display_filter(rows, "ip.src == 10.0.0.5 and risk >= 60")), 1)
        self.assertEqual(len(apply_display_filter(rows, 'contains "authorization"')), 2)
        self.assertTrue(compile_display_filter("tcp.port == 443")(rows[1]))
        with self.assertRaises(DisplayFilterError):
            compile_display_filter("ip.src ==")

    def test_stream_and_expert_outputs_are_redacted(self):
        stream = reconstruct_stream([self.packet()], flow_id="flow-1", protocol="HTTP", capture_mode="full")
        expert = packet_expert_items(self.packet(direction="OUTGOING"))
        flow_expert = flow_expert_items({"flow_id": "flow-1", "packets_count": 1200, "bytes_total": 20_000_000, "related_alert_ids": ["1", "2", "3"], "app_protocol": "UNKNOWN"})
        self.assertNotIn("raw-secret", str(stream))
        self.assertTrue(expert)
        self.assertGreaterEqual(len(flow_expert), 3)


if __name__ == "__main__":
    unittest.main()
