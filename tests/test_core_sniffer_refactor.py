import sys
import types
import unittest
from unittest.mock import patch

from backend.app.bootstrap import ensure_project_root_on_path

ensure_project_root_on_path()

from core.core_sniffer import NetSniffer
from core.netbotpro_sniffer_core.packet_parser import PacketLayers, PacketMetadataBuilder


class _FakeLayer:
    def __init__(self, **attrs):
        for key, value in attrs.items():
            setattr(self, key, value)


class _FakePacket:
    def __init__(self):
        self._layers = {}

    def set_layer(self, layer_type, layer):
        self._layers[layer_type] = layer
        return self

    def __contains__(self, item):
        return item in self._layers

    def __getitem__(self, item):
        return self._layers[item]

    def haslayer(self, item):
        return item in self._layers

    def summary(self):
        return "fake-summary"

    def __len__(self):
        return 128


class _Ether:
    pass


class _IP:
    pass


class _TCP:
    pass


class _UDP:
    pass


class _ICMP:
    pass


class _DNS:
    pass


class _DNSQR:
    pass


class _Geo:
    def lookup(self, ip_addr):
        return {"country": "US", "country_name": "United States", "org": "Example ISP"}


class _Vendor:
    def lookup(self, mac_addr):
        return "Vendor"


class _Process:
    def resolve(self, local_ip, local_port, proto):
        return {"pid": 1234, "process_name": "proc"}


class CoreSnifferRefactorTests(unittest.TestCase):
    def test_wrapper_exposes_netsniffer_class(self):
        callback = lambda meta: None
        sniffer = NetSniffer(callback, sniff_func=lambda **kwargs: None)
        self.assertTrue(hasattr(sniffer, "start"))
        self.assertTrue(hasattr(sniffer, "stop"))

    def test_default_sniff_import_registers_ethernet_linktype(self):
        from core.netbotpro_sniffer_core import runtime

        def fake_sniff(**_kwargs):
            return None

        register_calls = []
        fake_ether = object()
        fake_config = types.ModuleType("scapy.config")
        fake_config.conf = types.SimpleNamespace(
            l2types=types.SimpleNamespace(register=lambda *args: register_calls.append(args))
        )
        fake_layers_l2 = types.ModuleType("scapy.layers.l2")
        fake_layers_l2.Ether = fake_ether
        fake_sendrecv = types.ModuleType("scapy.sendrecv")
        fake_sendrecv.sniff = fake_sniff

        with (
            patch.object(runtime, "ensure_capture_backend", return_value=None),
            patch.dict(
                sys.modules,
                {
                    "scapy.config": fake_config,
                    "scapy.layers.l2": fake_layers_l2,
                    "scapy.sendrecv": fake_sendrecv,
                },
            ),
        ):
            sniffer = runtime.NetSniffer(lambda _meta: None)
            sniff_func = sniffer._sniff_callable()

        self.assertIs(sniff_func, fake_sniff)
        self.assertIs(sniffer._sniff_func, fake_sniff)
        self.assertEqual(register_calls, [(1, fake_ether)])

    def test_packet_builder_keeps_compatibility_aliases(self):
        layers = PacketLayers(Ether=_Ether, IP=_IP, TCP=_TCP, UDP=_UDP, ICMP=_ICMP, DNS=_DNS, DNSQR=_DNSQR)
        builder = PacketMetadataBuilder(
            layers=layers,
            geoip_provider=_Geo(),
            mac_vendor_provider=_Vendor(),
            process_mapper=_Process(),
            timestamp_factory=lambda: "10:00:00",
        )
        pkt = (
            _FakePacket()
            .set_layer(_Ether, _FakeLayer(src="aa:bb", dst="cc:dd"))
            .set_layer(_IP, _FakeLayer(src="192.168.1.10", dst="8.8.8.8", ttl=64, proto=6))
            .set_layer(_TCP, _FakeLayer(sport=44444, dport=443, flags="S", payload=b""))
        )

        meta = builder.build(pkt)

        self.assertEqual(meta["ts"], "10:00:00")
        self.assertEqual(meta["timestamp"], "10:00:00")
        self.assertEqual(meta["country_code"], "US")
        self.assertEqual(meta["remote_ip"], "8.8.8.8")
        self.assertIn("sni", meta)
        self.assertIn("alpn", meta)

    def test_packet_builder_uses_explicit_local_ips_for_public_address_interfaces(self):
        layers = PacketLayers(Ether=_Ether, IP=_IP, TCP=_TCP, UDP=_UDP, ICMP=_ICMP, DNS=_DNS, DNSQR=_DNSQR)
        builder = PacketMetadataBuilder(
            layers=layers,
            local_ips={"93.184.216.35"},
            geoip_provider=_Geo(),
            mac_vendor_provider=_Vendor(),
            process_mapper=_Process(),
            timestamp_factory=lambda: "10:00:00",
        )
        pkt = (
            _FakePacket()
            .set_layer(_Ether, _FakeLayer(src="aa:bb", dst="cc:dd"))
            .set_layer(_IP, _FakeLayer(src="93.184.216.35", dst="1.1.1.1", ttl=64, proto=6))
            .set_layer(_TCP, _FakeLayer(sport=44444, dport=443, flags="S", payload=b""))
        )

        meta = builder.build(pkt)

        self.assertEqual(meta["direction"], "OUTGOING")
        self.assertEqual(meta["remote_ip"], "1.1.1.1")

    def test_packet_builder_extracts_http_response_metadata(self):
        layers = PacketLayers(Ether=_Ether, IP=_IP, TCP=_TCP, UDP=_UDP, ICMP=_ICMP, DNS=_DNS, DNSQR=_DNSQR)
        builder = PacketMetadataBuilder(
            layers=layers,
            geoip_provider=_Geo(),
            mac_vendor_provider=_Vendor(),
            process_mapper=_Process(),
            timestamp_factory=lambda: "10:00:00",
        )
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: unit-test\r\n\r\n{}"
        pkt = (
            _FakePacket()
            .set_layer(_Ether, _FakeLayer(src="aa:bb", dst="cc:dd"))
            .set_layer(_IP, _FakeLayer(src="8.8.8.8", dst="192.168.1.10", ttl=64, proto=6))
            .set_layer(_TCP, _FakeLayer(sport=8088, dport=54000, flags="PA", payload=payload))
        )

        meta = builder.build(pkt)

        self.assertEqual(meta["http_status"], 200)
        self.assertEqual(meta["http_reason"], "OK")
        self.assertEqual(meta["http_content_type"], "application/json")
        self.assertEqual(meta["l7"], "HTTP RESPONSE 200")


if __name__ == "__main__":
    unittest.main()
