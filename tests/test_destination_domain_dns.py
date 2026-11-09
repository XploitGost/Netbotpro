import unittest

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP

from core.netbotpro_sniffer_core.layer7 import extract_layer7


class DestinationDomainDnsTests(unittest.TestCase):
    def test_dns_response_exposes_bounded_answer_ips(self):
        packet = (
            IP(src="8.8.8.8", dst="10.0.0.5")
            / UDP(sport=53, dport=50000)
            / DNS(qr=1, qd=DNSQR(qname="example.net"),
                  an=DNSRR(rrname="example.net", type="A", rdata="203.0.113.7"))
        )
        import scapy.all as layers

        result = extract_layer7(packet, bytes(packet[UDP].payload), layers)
        self.assertEqual(result["dns_qname"], "example.net.")
        self.assertEqual(result["dns_answer_ips"], ["203.0.113.7"])

    def test_dns_query_has_no_answer_ips(self):
        packet = IP(src="10.0.0.5", dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname="example.net"))
        import scapy.all as layers

        result = extract_layer7(packet, bytes(packet[UDP].payload), layers)
        self.assertEqual(result["dns_answer_ips"], [])
