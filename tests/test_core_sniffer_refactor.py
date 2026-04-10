import unittest

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
        self.assertIn("sni", meta)
        self.assertIn("alpn", meta)


if __name__ == "__main__":
    unittest.main()
