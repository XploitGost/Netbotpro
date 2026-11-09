import gc
import random
import unittest
import weakref
from unittest.mock import patch

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, Dot1Q, ARP
from scapy.packet import Raw, Padding
from scapy.config import conf

from core.netbotpro_sniffer_core.packet_parser import PacketLayers, PacketMetadataBuilder
from core.protocol_intelligence import analyze_protocol


class EmptyProvider:
    def lookup(self, *args):
        return {}

    def resolve(self, *args):
        return {}


def frame():
    return Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')


def builder():
    return PacketMetadataBuilder(
        PacketLayers(Ether=Ether, IP=IP, TCP=TCP, UDP=UDP, ICMP=ICMP, DNS=DNS, DNSQR=DNSQR),
        local_ips={'192.0.2.1'}, geoip_provider=EmptyProvider(),
        mac_vendor_provider=EmptyProvider(), process_mapper=EmptyProvider(),
        timestamp_factory=lambda: '2026-11-08T12:00:00+00:00')


class CaptureMetadataWorkTests(unittest.TestCase):
    def test_classification_only_matches_full_result_without_metadata_walk(self):
        cases = [dict(proto='TCP', dport=443), dict(proto='TCP', dport=22),
                 dict(proto='ICMP'), dict(proto='OTHER'), dict(proto='TCP', app_protocol='TLS'),
                 dict(proto='UDP', dns_qname='example.test', dns_qtype='A'),
                 dict(proto='TCP', http_method='GET', http_host='example.test',
                      http_path='/?token=private'), dict(proto='TCP', tls_sni='example.test')]
        for packet in cases:
            expected = analyze_protocol(packet)
            with patch('core.protocol_intelligence._safe_metadata', side_effect=AssertionError('metadata built twice')):
                actual = analyze_protocol(packet, include_metadata=False)
            self.assertEqual(actual, {**expected, 'metadata': {}})
        self.assertNotIn('private', str(analyze_protocol(cases[-2])['metadata']))

    def test_bytes_classification_matches_old_hex_and_text_input(self):
        rng = random.Random(2419)
        payloads = [b'', b'GET / HTTP/1.1\r\n', b'PATCH / HTTP/1.1\r\n', b'SSH-2.0-test',
                    b'\x16\x03\x03\x00\x20' + b'x' * 32, b'\xffSMB', b'\xfeSMB',
                    b'\x03\x00test', b'220 smtp', b'+OK', b'* OK', bytes(range(256))]
        payloads += [rng.randbytes(rng.randrange(257)) for _ in range(200)]
        for raw in payloads:
            packet = dict(proto='TCP', sport=50000, dport=50001)
            expected = analyze_protocol({**packet, 'payload_hex': raw.hex(),
                                         'payload_ascii': raw.decode('latin-1')})
            actual = analyze_protocol(packet, payload_bytes=raw, include_metadata=False)
            self.assertEqual(actual, {**expected, 'metadata': {}}, repr(raw))

    def test_builder_output_matches_full_classification(self):
        packets = [frame()/IP(src='192.0.2.1', dst='198.51.100.2')/TCP(dport=443)/Raw(b'abc'),
                   frame()/IP()/UDP(dport=53)/DNS(qd=DNSQR(qname='example.test')),
                   frame()/IP()/UDP(sport=53)/DNS(qr=1, qd=DNSQR(qname='example.test'),
                                                an=DNSRR(rrname='example.test', rdata='1.1.1.1')),
                   frame()/Dot1Q(vlan=2)/IP()/ICMP(), frame()/IPv6()/TCP(dport=443),
                   frame()/ARP(), frame()/IP()/TCP(dport=8080)/Raw(b'GET /?token=private HTTP/1.1\r\nHost: example.test\r\n\r\n')]
        def old_classifier(packet, *, payload_bytes=None, **kwargs):
            if payload_bytes is not None:
                packet = {**packet, 'payload_hex': payload_bytes.hex(),
                          'payload_ascii': payload_bytes.decode('latin-1')}
            return analyze_protocol(packet)
        for packet in packets:
            with patch('core.protocol_intelligence.analyze_protocol', side_effect=old_classifier):
                expected = builder().build(packet)
            self.assertEqual(builder().build(packet), expected)

    def test_no_packet_is_retained_after_metadata_build(self):
        packet = frame()/IP()/TCP()/Raw(b'discard after build')
        reference = weakref.ref(packet)
        metadata_builder = builder()
        metadata_builder.build(packet)
        del packet
        gc.collect()
        self.assertIsNone(reference())

    def test_plain_tcp_summaries_match_scapy_with_flags_ports_and_padding(self):
        metadata_builder = builder()
        for flags in ('', 'S', 'A', 'FA', 'R', 'PA', 'SEC'):
            for sport, dport in ((20, 80), (50000, 443), (443, 50000), (0, 65535)):
                for suffix in (None, Raw(b'GET / secret bytes'), Padding(b'pad'), Raw(b'x')/Padding(b'pad')):
                    packet = frame()/IP(src='192.0.2.1', dst='198.51.100.2')/TCP(sport=sport, dport=dport, flags=flags)
                    if suffix is not None:
                        packet = packet/suffix
                    self.assertEqual(metadata_builder._plain_tcp_summary(packet), packet.summary())
                    self.assertEqual(metadata_builder._safe_summary(packet), packet.summary())
                    self.assertEqual(metadata_builder._safe_summary(packet[IP]), packet[IP].summary())

    def test_summary_fallback_preserves_nonstandard_and_payload_sensitive_formatting(self):
        metadata_builder = builder()
        packet = frame()/IP()/TCP()/Raw(b'secret payload')
        previous = conf.raw_summary
        try:
            conf.raw_summary = True
            self.assertIsNone(metadata_builder._plain_tcp_summary(packet))
            self.assertEqual(metadata_builder._safe_summary(packet), packet.summary())
        finally:
            conf.raw_summary = previous
        for packet in (frame()/IP()/UDP()/DNS(qd=DNSQR(qname='example.test')),
                       frame()/Dot1Q(vlan=2)/IP()/TCP(), frame()/IPv6()/TCP(), frame()/ARP()):
            self.assertIsNone(metadata_builder._plain_tcp_summary(packet))
            self.assertEqual(metadata_builder._safe_summary(packet), packet.summary())

    def test_fast_summary_error_uses_original_summary(self):
        packet = frame()/IP()/TCP()
        with patch.object(PacketMetadataBuilder, '_plain_tcp_summary', side_effect=ValueError('unavailable')):
            self.assertEqual(builder()._safe_summary(packet), packet.summary())

    def test_custom_scapy_formatting_is_not_bypassed(self):
        packet = frame()/IP()/TCP()
        metadata_builder = builder()
        for setting in (conf.resolve, conf.emph, conf.noenum):
            fields, layers = setting.fields.copy(), setting.layers.copy()
            try:
                setting.add(IP().get_field('src'))
                self.assertIsNone(metadata_builder._plain_tcp_summary(packet))
            finally:
                setting.fields.clear()
                setting.fields.update(fields)
                setting.layers.clear()
                setting.layers.update(layers)
