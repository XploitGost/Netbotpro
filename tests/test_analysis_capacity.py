import ipaddress
import os
import unittest
from collections import Counter
from copy import deepcopy
from unittest.mock import patch

from backend.app.services.capture_policy import current_capture_policy, current_payload_capture_settings
from backend.app.services.service_attribution import _safe_ip, _cached_ip
from backend.app.services.sniffer_service import SnifferService
from core.flow_engine import _detach_summary_value


class AnalysisCapacityTests(unittest.TestCase):
    def test_payload_decision_matches_full_policy(self):
        for mode in ('metadata', 'full', 'forensic', 'invalid', ''):
            for enabled in (True, False):
                for override in ('', 'metadata', 'full'):
                    with self.subTest(mode=mode, enabled=enabled, override=override):
                        with patch.dict(os.environ, {'NETBOT_CAPTURE_MODE': override,
                                                     'NETBOT_PAYLOAD_CAPTURE': ''}, clear=True):
                            with patch('backend.app.services.capture_policy.get_settings_snapshot',
                                       return_value={'capture_mode': mode, 'payload_capture_enabled': enabled}):
                                full = current_capture_policy().to_public_dict()
                                fast = current_payload_capture_settings()
                                self.assertEqual(fast['capture_mode'], full['capture_mode'])
                                self.assertEqual(fast['payload_capture_enabled'], full['payload_capture_enabled'])

    def test_payload_settings_refresh_and_alert_only_is_enforced(self):
        settings = {'capture_mode': 'full', 'payload_capture_enabled': True}
        with patch.dict(os.environ, {}, clear=True):
            with patch('backend.app.services.capture_policy.get_settings_snapshot', side_effect=lambda: dict(settings)):
                self.assertTrue(current_payload_capture_settings()['payload_capture_enabled'])
                settings['alert_only_mode'] = True
                row = {'payload_hex': 'aa', 'payload_ascii': 'private'}
                SnifferService._apply_payload_policy(row, current_payload_capture_settings())
                self.assertEqual(row, {'payload_hex': '', 'payload_ascii': ''})
                settings['capture_mode'] = 'metadata'
                self.assertFalse(current_payload_capture_settings()['payload_capture_enabled'])
                os.environ.update(NETBOT_CAPTURE_MODE='forensic', NETBOT_PAYLOAD_CAPTURE='1')
                settings['alert_only_mode'] = False
                row = {'payload_hex': 'aa', 'payload_ascii': 'allowed'}
                SnifferService._apply_payload_policy(row, current_payload_capture_settings())
                self.assertEqual(row['payload_ascii'], 'allowed')

    def test_ip_cache_parity_bounds_and_oversized_input(self):
        _cached_ip.cache_clear()
        for value in (None, '', ' 8.8.8.8 ', '::1', '2001:db8::2', 'fe80::1%12',
                      'example.test', '999.1.2.3', 'a' * 1000, 123):
            try:
                expected = str(ipaddress.ip_address(str(value or '').strip()))
            except ValueError:
                expected = ''
            self.assertEqual(_safe_ip(value), expected)
        for number in range(5000):
            _safe_ip(str(ipaddress.IPv4Address(number)))
        self.assertLessEqual(_cached_ip.cache_info().currsize, 4096)
        before = _cached_ip.cache_info()
        _safe_ip('x' * 100000)
        self.assertEqual(_cached_ip.cache_info(), before)
        _cached_ip.cache_clear()
        _safe_ip('8.8.8.8')
        with patch('backend.app.services.service_attribution.ipaddress.ip_address', side_effect=AssertionError('parsed twice')):
            self.assertEqual(_safe_ip('8.8.8.8'), '8.8.8.8')
        _cached_ip.cache_clear()

    def test_summary_copies_preserve_types_and_detach_nested_values(self):
        for value in (None, 1, 'text', [], ['a', 2], {'a': 1}, Counter(high=2),
                      [{'nested': ['original']}], {'a': ['original']}, ('a', ['b'])):
            original = deepcopy(value)
            copied = _detach_summary_value(value)
            self.assertEqual(copied, original)
            self.assertIs(type(copied), type(value))
            if isinstance(value, (dict, list)):
                self.assertIsNot(copied, value)
        nested = {'a': ['original']}
        copied = _detach_summary_value(nested)
        copied['a'].append('changed')
        self.assertEqual(nested, {'a': ['original']})
