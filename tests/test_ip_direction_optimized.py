import ipaddress
import unittest
from unittest.mock import patch

from core.netbotpro_sniffer_core import ip_utils as ip


def previous_preferred(*candidates, local_ips=None):
    for candidate in candidates:
        normalized = ip.normalize_ip(candidate)
        if normalized and ip.is_remote_ip(normalized, local_ips=local_ips):
            return normalized
    for candidate in candidates:
        normalized = ip.normalize_ip(candidate)
        if normalized:
            return normalized
    return None


def previous_infer(src, dst, local_ips=None):
    src_local, dst_local = ip.is_local_ip(src, local_ips=local_ips), ip.is_local_ip(dst, local_ips=local_ips)
    src_remote, dst_remote = ip.is_remote_ip(src, local_ips=local_ips), ip.is_remote_ip(dst, local_ips=local_ips)
    direction, remote = 'OTHER', previous_preferred(dst, src, local_ips=local_ips)
    if src_local and dst_remote:
        direction, remote = 'OUTGOING', previous_preferred(dst, src, local_ips=local_ips)
    elif src_remote and dst_local:
        direction, remote = 'INCOMING', previous_preferred(src, dst, local_ips=local_ips)
    elif src_local and dst_local:
        direction, remote = 'LOCAL', ip.normalize_ip(dst) or ip.normalize_ip(src)
    return dict(direction=direction, remote_ip=remote)


class DirectionOptimizationTests(unittest.TestCase):
    def test_results_match_previous_ipv4_ipv6_invalid_and_explicit_local(self):
        values = [None, '', 'invalid', '8.8.8.8', '1.1.1.1', '192.168.1.1',
                  '100.64.1.1', '127.0.0.1', '224.0.0.1', '::1',
                  'fe80::1%zone', '2606:4700:4700::1111', ipaddress.ip_address('8.8.8.8'), 0,
                  ipaddress.ip_address('2606:4700:4700::1111%zone')]
        for local in (None, set(), {'8.8.8.8'}, {'192.168.1.1', '2606:4700:4700::1111'}, {'2606:4700:4700::1111%zone'}):
            for src in values:
                for dst in values:
                    self.assertEqual(ip.infer_flow(src, dst, local_ips=local), previous_infer(src, dst, local))
                    self.assertEqual(ip.preferred_remote_ip(src, dst, local_ips=local), previous_preferred(src, dst, local_ips=local))

    def test_each_valid_address_is_parsed_only_once(self):
        with patch.object(ip.ipaddress, 'ip_address', wraps=ip.ipaddress.ip_address) as parse:
            ip.infer_flow('192.168.1.1', '8.8.8.8', local_ips=set())
        self.assertEqual(parse.call_count, 2)
