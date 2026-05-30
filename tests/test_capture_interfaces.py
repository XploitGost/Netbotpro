from __future__ import annotations

import unittest
from unittest.mock import patch

from core.netbotpro_sniffer_core.interfaces import (
    describe_capture_interface,
    list_capture_interfaces,
    recommended_interface_name,
    resolve_capture_interface,
)


FAKE_INTERFACES = [
    {
        "value": r"\\Device\\NPF_{ETH}",
        "name": "Ethernet",
        "description": "Realtek Gaming 2.5GbE Family Controller",
        "ip": "192.168.100.4",
        "network_name": r"\\Device\\NPF_{ETH}",
        "label": "Ethernet - Realtek Gaming 2.5GbE Family Controller - 192.168.100.4",
    },
    {
        "value": r"\\Device\\NPF_Loopback",
        "name": "Loopback Pseudo-Interface 1",
        "description": "Software Loopback Interface 1",
        "ip": "127.0.0.1",
        "network_name": r"\\Device\\NPF_Loopback",
        "label": "Loopback Pseudo-Interface 1 - Software Loopback Interface 1 - 127.0.0.1",
    },
]

FAKE_MIXED_INTERFACES = [
    {
        "value": r"\\Device\\NPF_{VMNET}",
        "name": "VMware Network Adapter VMnet8",
        "description": "VMware Virtual Ethernet Adapter for VMnet8",
        "ip": "192.168.56.1",
        "network_name": r"\\Device\\NPF_{VMNET}",
        "label": "VMware Network Adapter VMnet8 - 192.168.56.1",
    },
    {
        "value": r"\\Device\\NPF_{ETH}",
        "name": "Ethernet",
        "description": "Realtek Gaming 2.5GbE Family Controller",
        "ip": "192.168.100.4",
        "network_name": r"\\Device\\NPF_{ETH}",
        "label": "Ethernet - Realtek Gaming 2.5GbE Family Controller - 192.168.100.4",
    },
]


class CaptureInterfacesTests(unittest.TestCase):
    @patch("core.netbotpro_sniffer_core.interfaces._scapy_interfaces", return_value=FAKE_INTERFACES)
    @patch("core.netbotpro_sniffer_core.interfaces._detect_primary_local_ip", return_value="192.168.100.4")
    def test_recommended_interface_prefers_scapy_match(self, *_mocks):
        self.assertEqual(recommended_interface_name(), r"\\Device\\NPF_{ETH}")

    @patch("core.netbotpro_sniffer_core.interfaces._scapy_interfaces", return_value=FAKE_MIXED_INTERFACES)
    @patch("core.netbotpro_sniffer_core.interfaces._detect_primary_local_ip", return_value=None)
    def test_recommended_interface_prefers_physical_adapter_over_virtual(self, *_mocks):
        self.assertEqual(recommended_interface_name(), r"\\Device\\NPF_{ETH}")

    @patch("core.netbotpro_sniffer_core.interfaces._scapy_interfaces", return_value=FAKE_INTERFACES)
    def test_resolve_capture_interface_accepts_friendly_name(self, _mock_interfaces):
        self.assertEqual(resolve_capture_interface("Ethernet"), r"\\Device\\NPF_{ETH}")
        self.assertEqual(resolve_capture_interface(r"\\Device\\NPF_{ETH}"), r"\\Device\\NPF_{ETH}")
        self.assertIsNone(resolve_capture_interface("am"))

    @patch("core.netbotpro_sniffer_core.interfaces._scapy_interfaces", return_value=FAKE_INTERFACES)
    @patch("core.netbotpro_sniffer_core.interfaces.recommended_interface_name", return_value=r"\\Device\\NPF_{ETH}")
    def test_list_capture_interfaces_exposes_friendly_recommended_label(self, *_mocks):
        result = list_capture_interfaces()
        self.assertEqual(result["recommended"], r"\\Device\\NPF_{ETH}")
        self.assertEqual(result["recommended_label"], "Ethernet")
        self.assertEqual(result["items"][0]["value"], r"\\Device\\NPF_{ETH}")
        self.assertEqual(describe_capture_interface(r"\\Device\\NPF_{ETH}"), "Ethernet")


if __name__ == "__main__":
    unittest.main()
