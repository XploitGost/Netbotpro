import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from core.ids_signature import SignatureIDS
from core.scan_response_context import ScanResponseContext
from backend.app.services.sniffer_detection_pipeline import SnifferDetectionPipeline

ORIGIN = datetime(2026, 11, 8, tzinfo=timezone.utc)


def request(port=50000, *, proto='TCP', flags='PA', at=0, **extra):
    return dict(src='192.0.2.10', dst='198.51.100.20', sport=port, dport=443,
                proto=proto, flags=flags, direction='OUTGOING',
                ts=(ORIGIN + timedelta(seconds=at)).isoformat(), **extra)


def reply(packet, *, flags='A', at=0, **extra):
    return {**packet, 'src': packet['dst'], 'dst': packet['src'],
            'sport': packet['dport'], 'dport': packet['sport'],
            'direction': 'INCOMING', 'flags': flags,
            'ts': (ORIGIN + timedelta(seconds=at)).isoformat(), **extra}


def detector():
    result = SignatureIDS()
    result.custom_rules = []
    result.flood_threshold = result.syn_threshold = 1000000
    return result


class ScanResponseTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, NETBOT_CAPTURE_JOURNAL='1')
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_tcp_handshake_and_data_responses_do_not_scan_client_ports(self):
        ids = detector()
        alerts = []
        for port in range(50000, 50020):
            sent = request(port, flags='S')
            for packet in (sent, reply(sent, flags='SA'), request(port), reply(sent, flags='PA')):
                if alert := ids.analyze_packet(packet):
                    alerts.append(alert)
        self.assertEqual(alerts, [])
        self.assertNotIn(('198.51.100.20', '192.0.2.10'), ids.port_scan_map)
        self.assertEqual(ids.port_scan_stats()['correlated_responses_total'], 60)

    def test_midstream_outgoing_data_can_correlate_a_later_reply(self):
        ids = detector()
        for port in range(50000, 50020):
            sent = request(port)
            self.assertIsNone(ids.analyze_packet(sent))
            self.assertIsNone(ids.analyze_packet(reply(sent)))

    def test_unknown_acks_are_not_blanket_exempted(self):
        ids = detector()
        for port in (22, 23, 24):
            alert = ids.analyze_packet(reply(request(port)))
        self.assertEqual(alert['attack_type'], 'Port Scan / Nmap-like')

    def test_real_probe_flags_remain_detectable_even_on_known_tuples(self):
        for flags in ('S', '', 'F', 'FPU', 2, 0):
            with self.subTest(flags=flags):
                ids = detector()
                for port in (50000, 50001, 50002):
                    sent = request(port)
                    ids.analyze_packet(sent)
                    alert = ids.analyze_packet(reply(sent, flags=flags))
                self.assertEqual(alert['attack_type'], 'Port Scan / Nmap-like')

    def test_udp_scan_behavior_is_not_changed_by_tcp_reply_hints(self):
        ids = detector()
        for port in range(50000, 50003):
            sent = request(port, proto='UDP', flags='')
            ids.analyze_packet(sent)
            alert = ids.analyze_packet(reply(request(port, proto='UDP', flags=''), flags=''))
        self.assertEqual(alert['attack_type'], 'Port Scan / Nmap-like')

    def test_rst_responses_do_not_turn_the_scan_victim_into_a_scanner(self):
        for flags in ('A', '', 'F', 'FPU'):
            ids = detector()
            for port in (22, 23, 24):
                probe = reply(request(50000), flags=flags, sport=40000+port, dport=port)
                alert = ids.analyze_packet(probe)
                response = reply(probe, flags='RA')
                self.assertIsNone(ids.analyze_packet(response))
            self.assertEqual(alert['attack_type'], 'Port Scan / Nmap-like')

    def test_midstream_first_reply_is_not_whitelisted_but_reverse_ack_supplies_context(self):
        ids = detector()
        sent = request()
        self.assertIsNone(ids.analyze_packet(reply(sent)))
        self.assertIsNone(ids.analyze_packet(sent))
        for _ in range(10):
            self.assertIsNone(ids.analyze_packet(reply(sent)))
        self.assertEqual(len(ids.port_scan_map[(sent['dst'], sent['src'])]), 1)

    def test_correlated_responses_still_participate_in_flood_and_custom_rules(self):
        ids = detector()
        sent = request()
        ids.analyze_packet(sent)
        ids.flood_threshold = 1
        self.assertEqual(ids.analyze_packet(reply(sent))['attack_type'], 'Generic Flood / High Rate')
        ids.flood_threshold = 1000000
        ids.custom_rules = [{'name': 'explicit rule', 'enabled': True,
                             'dport': 50000, 'window_sec': 10, 'count_threshold': 1}]
        self.assertEqual(ids.analyze_packet(reply(sent))['attack_type'], 'explicit rule')

    def test_numeric_ack_flags_and_syn_flood_still_work(self):
        ids = detector()
        sent = request(flags=2)
        ids.analyze_packet(sent)
        self.assertIsNone(ids.analyze_packet(reply(sent, flags=16)))
        ids.syn_threshold = 2
        self.assertEqual(ids.analyze_packet(sent)['attack_type'], 'SYN Flood')

    def test_repeated_reports_are_coalesced_but_expansion_and_periodic_update_emit(self):
        ids = detector()
        for port in (22, 23, 24):
            initial = ids.analyze_packet(reply(request(port)))
        self.assertEqual(initial['coalesced_occurrences'], 1)
        for _ in range(20):
            self.assertIsNone(ids.analyze_packet(reply(request(24))))
        expanded = ids.analyze_packet(reply(request(25)))
        self.assertEqual(expanded['score'], 4)
        self.assertEqual(expanded['coalesced_occurrences'], 21)
        self.assertIsNone(ids.analyze_packet(reply(request(25))))
        periodic = ids.analyze_packet(reply(request(25), at=10))
        self.assertEqual(periodic['coalesced_occurrences'], 2)
        self.assertEqual(ids.port_scan_stats()['reports_coalesced_total'], 21)

    def test_below_threshold_and_parameter_change_permit_new_report(self):
        ids = detector()
        for port in (22, 23, 24):
            ids.analyze_packet(reply(request(port)))
        self.assertIsNone(ids.analyze_packet(reply(request(24), at=11)))
        self.assertIsNone(ids.analyze_packet(reply(request(23), at=11)))
        self.assertIsNotNone(ids.analyze_packet(reply(request(22), at=11)))
        ids.update_params(port_scan_threshold=2)
        self.assertIsNotNone(ids.analyze_packet(reply(request(22), at=11)))

    def test_reset_clears_context_without_changing_configured_thresholds_or_rules(self):
        ids = detector()
        sent = request()
        ids.analyze_packet(sent)
        rules = ids.custom_rules
        ids.reset_runtime()
        self.assertEqual(ids.port_scan_stats()['tracked_flows'], 0)
        self.assertEqual(len(ids.flood_counter), 0)
        self.assertIs(ids.custom_rules, rules)
        self.assertEqual(ids.flood_threshold, 1000000)

    def test_report_cache_is_bounded_and_eviction_does_not_exempt_new_scans(self):
        ids = detector()
        ids._scan_reports_max = 2
        for source in ('198.51.100.1', '198.51.100.2', '198.51.100.3'):
            for port in (22, 23, 24):
                alert = ids.analyze_packet(reply(request(port), src=source))
            self.assertIsNotNone(alert)
        self.assertEqual(ids.port_scan_stats()['tracked_reports'], 2)
        self.assertEqual(ids.port_scan_stats()['report_capacity_evictions_total'], 1)
        self.assertIsNotNone(ids.analyze_packet(reply(request(24), src='198.51.100.1')))


class FlowHintTests(unittest.TestCase):
    def test_exact_tuple_and_interface_scope_are_required(self):
        context = ScanResponseContext()
        sent = request(iface='one')
        context.observe(sent, ORIGIN, 'PA')
        expected = reply(sent)
        for changed in (dict(src='198.51.100.21'), dict(dst='192.0.2.11'),
                        dict(sport=444), dict(dport=50001), dict(proto='UDP'), dict(iface='two')):
            self.assertFalse(context.observe({**expected, **changed}, ORIGIN, 'A'))
        self.assertTrue(context.observe(expected, ORIGIN, 'A'))

    def test_expiry_boundary_refresh_and_future_requests(self):
        sent = request()
        context = ScanResponseContext(idle_seconds=60)
        context.observe(sent, ORIGIN, 'PA')
        self.assertFalse(context.observe(reply(sent), ORIGIN - timedelta(seconds=1), 'A'))
        self.assertTrue(context.observe(reply(sent), ORIGIN + timedelta(seconds=60), 'A'))
        self.assertTrue(context.observe(reply(sent), ORIGIN + timedelta(seconds=120), 'A'))
        self.assertFalse(context.observe(reply(sent), ORIGIN + timedelta(seconds=180, microseconds=1), 'A'))
        context.expire(ORIGIN + timedelta(seconds=241))
        self.assertEqual(context.stats()['tracked_flows'], 0)

    def test_capacity_and_invalid_input_fall_back_conservatively(self):
        context = ScanResponseContext(max_flows=2)
        for port in range(50000, 50010):
            context.observe(request(port), ORIGIN, 'PA')
        self.assertEqual(context.stats()['tracked_flows'], 2)
        self.assertEqual(context.stats()['capacity_evictions_total'], 8)
        self.assertFalse(context.observe(reply(request(50000)), ORIGIN, 'A'))
        for changed in ({'sport': None}, {'dport': -1}, {'src': 'x'*1000}, {'iface': 'x'*1000}):
            self.assertFalse(context.observe({**request(), **changed}, ORIGIN, 'PA'))
        self.assertEqual(context.stats()['tracked_flows'], 2)

    def test_rst_removes_both_reply_hints_before_later_ack_probes(self):
        context = ScanResponseContext()
        sent = request()
        context.observe(sent, ORIGIN, 'PA')
        context.observe(reply(sent), ORIGIN, 'A')
        self.assertTrue(context.observe(reply(sent, flags='RA'), ORIGIN, 'RA'))
        self.assertEqual(context.stats()['tracked_flows'], 0)
        self.assertFalse(context.observe(reply(sent), ORIGIN, 'A'))


class ScanPipelineTests(unittest.TestCase):
    def test_occurrence_count_and_context_metrics_survive_pipeline(self):
        engine = SignatureIDS()
        pipeline = SnifferDetectionPipeline(ids_sig=engine, scorer=Mock(), incidents=Mock())
        raw = {'attack_type': 'Port Scan / Nmap-like', 'score': 3, 'coalesced_occurrences': 10}
        result = pipeline._build_alert_payload(request(), raw)
        self.assertEqual(result['coalesced_occurrences'], 10)
        self.assertEqual(pipeline.health_stats()['port_scan_context']['max_flows'], 8192)
        pipeline.reset_signature_context()
        self.assertEqual(engine.port_scan_stats()['tracked_flows'], 0)
