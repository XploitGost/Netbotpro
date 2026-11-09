import unittest
from dataclasses import asdict, dataclass
from unittest.mock import patch

from backend.app.services.sniffer_dashboard_state import _remote_ip
from core.flow_engine import FlowEngine
from backend.app.services.service_attribution import ServiceAttributionResult
from core.privacy_redaction import redact_sensitive_data


class AnalysisHotPathTests(unittest.TestCase):
    def test_service_result_single_copy_preserves_redaction_and_detachment(self):
        values = dict(application_name='example.exe', service_name='Example', service_category='Web',
                      domain='example.test', destination_ip='1.1.1.1', destination_port=443,
                      attribution_confidence='high', confidence_score=90,
                      attribution_reasons=('Cookie: a=secret', 'Authorization: Bearer fake-token'),
                      attribution_sources=('tls',), is_encrypted=True, is_unknown=False,
                      is_cdn=False, is_proxy_or_vpn_suspected=False, risk_hint='normal')
        result = ServiceAttributionResult(**values)
        for native in ('0', '1'):
            with patch.dict('os.environ', {'NETBOT_NATIVE_REDACTION': native}):
                public = result.to_dict()
                self.assertEqual(public, redact_sensitive_data(asdict(result)))
                public['attribution_reasons'].append('changed')
                self.assertEqual(len(result.attribution_reasons), 2)
        @dataclass(frozen=True)
        class ExtendedResult(ServiceAttributionResult):
            extra: str = 'token=fake-secret'
        extended = ExtendedResult(**values)
        self.assertEqual(extended.to_dict(), redact_sensitive_data(asdict(extended)))

    def test_adapter_aware_remote_reused_for_incoming_public_vpn_address(self):
        packet = dict(src='1.1.1.1', dst='104.37.1.162', direction='INCOMING', remote_ip='1.1.1.1')
        with patch('backend.app.services.sniffer_dashboard_state._preferred_remote_ip', side_effect=AssertionError('reclassified')):
            self.assertEqual(_remote_ip(packet), '1.1.1.1')

    def test_outgoing_and_local_consistent_metadata_need_no_ip_classification(self):
        for direction in ('OUTGOING', 'LOCAL'):
            packet = dict(src='10.0.0.1', dst='10.0.0.2', direction=direction, remote_ip='10.0.0.2')
            with patch('backend.app.services.sniffer_dashboard_state._preferred_remote_ip', side_effect=AssertionError('reclassified')):
                self.assertEqual(_remote_ip(packet), '10.0.0.2')

    def test_inconsistent_metadata_uses_legacy_fallback(self):
        packet = dict(src='192.168.1.2', dst='8.8.8.8', direction='OUTGOING', remote_ip='192.168.1.1')
        self.assertEqual(_remote_ip(packet), '8.8.8.8')

    def test_stable_attribution_reused_but_changed_input_stays_detached(self):
        engine = FlowEngine()
        attribution = {'safe': ['first']}
        packet = dict(src='10.0.0.1', dst='1.1.1.1', sport=50000, dport=443,
                      proto='TCP', direction='OUTGOING', length=60, ts='2026-11-07T12:00:00+00:00',
                      service_name='Example', service_attribution=attribution)
        flow = engine.ingest(packet, live_summary=True)
        stored = engine._flows[flow['flow_id']]['service_attribution']
        self.assertIsNot(stored, attribution)
        engine.ingest(packet, live_summary=True)
        self.assertIs(engine._flows[flow['flow_id']]['service_attribution'], stored)
        attribution['safe'].append('second')
        self.assertEqual(stored['safe'], ['first'])
        engine.ingest(packet, live_summary=True)
        updated = engine._flows[flow['flow_id']]['service_attribution']
        self.assertEqual(updated['safe'], ['first', 'second'])
        attribution['safe'].append('third')
        self.assertEqual(updated['safe'], ['first', 'second'])
