import threading
import unittest
from unittest.mock import Mock, patch

from core.netbotpro_sniffer_core.runtime import NetSniffer


class CaptureHandoverTests(unittest.TestCase):
    def test_failed_binding_is_not_a_valid_route_confirmation(self):
        sniffer, resolver = self.make_sniffer('vpn')
        failed = ('vpn', None, None, 'fixture adapter unavailable')
        ready = ('vpn', 'wan', 'host 192.0.2.10', '')
        self.assertEqual(sniffer._apply_capture_observation('wifi', failed), ('wifi', False))
        self.assertTrue(sniffer._route_warning)
        self.assertEqual(sniffer._apply_capture_observation('wifi', ready), ('wifi', False))
        self.assertEqual(sniffer.selected_iface(), 'Wi-Fi')
        self.assertEqual(sniffer._route_switches, 0)
        self.assertEqual(sniffer._apply_capture_observation('wifi', ready), ('wan', True))
        self.assertEqual(sniffer.selected_iface(), 'vpn')

    def test_error_between_good_observations_resets_route_confirmation(self):
        sniffer, resolver = self.make_sniffer('vpn')
        ready = ('vpn', 'wan', None, '')
        sniffer._apply_capture_observation('wifi', ready)
        sniffer._apply_capture_observation('wifi', ('vpn', None, None, 'fixture failure'))
        sniffer._apply_capture_observation('wifi', ready)
        self.assertEqual(sniffer.selected_iface(), 'Wi-Fi')
        sniffer._apply_capture_observation('wifi', ready)
        self.assertEqual(sniffer.selected_iface(), 'vpn')

    def test_confirmation_requires_stable_binding_not_just_profile_name(self):
        sniffer, resolver = self.make_sniffer('vpn')
        sniffer._apply_capture_observation('wifi', ('vpn', 'wan', 'host 192.0.2.1', ''))
        sniffer._apply_capture_observation('wifi', ('vpn', ['wan4', 'wan6'], 'host 192.0.2.2', ''))
        self.assertEqual(sniffer.selected_iface(), 'Wi-Fi')
        self.assertEqual(sniffer._apply_capture_observation('wifi',
            ('vpn', ['wan4', 'wan6'], 'host 192.0.2.2', '')), (['wan4', 'wan6'], True))

    def test_empty_capture_target_does_not_select_scapy_default(self):
        for target in (None, '', []):
            sniffer, _ = self.make_sniffer('vpn')
            self.assertEqual(sniffer._apply_capture_observation('wifi', ('vpn', target, None, '')),
                             ('wifi', False))
            self.assertEqual(sniffer.selected_iface(), 'Wi-Fi')
            self.assertEqual(sniffer._route_candidate_hits, 0)

    def test_old_binding_drains_before_selection_and_metadata_builder_change(self):
        sniffer, _ = self.make_sniffer('vpn')
        old_builder = sniffer._builder = object()
        observed = []
        ready = ('vpn', 'wan', 'host 192.0.2.10', '')
        with patch.object(sniffer, '_close_binding', side_effect=lambda: observed.append(
                (sniffer.selected_iface(), sniffer._builder))):
            sniffer._apply_capture_observation('wifi', ready)
            self.assertEqual(observed, [])
            sniffer._apply_capture_observation('wifi', ready)
        self.assertEqual(observed, [('Wi-Fi', old_builder)])
        self.assertIsNone(sniffer._builder)
        self.assertEqual(sniffer._route_switches, 1)

    def make_sniffer(self, route='Wi-Fi', manual=False):
        resolver = Mock(return_value=route)
        sniffer = NetSniffer(lambda packet: None, iface_resolver=resolver,
                             sniff_func=lambda **kwargs: None)
        sniffer._iface = 'Wi-Fi'
        sniffer._auto_interface = not manual
        sniffer._running = True
        return sniffer, resolver

    def test_auto_switch_keeps_session_and_rebuilds_metadata(self):
        sniffer, resolver = self.make_sniffer('ras:amir')
        builder = sniffer._builder = object()
        with patch.object(sniffer, '_capture_binding', return_value=('wan', 'host 10.0.0.2')):
            self.assertEqual(sniffer._refresh_capture_target('wifi'), ('wifi', True))
            self.assertIs(sniffer._builder, builder)
            self.assertEqual(sniffer._refresh_capture_target('wifi'), ('wan', True))
        self.assertEqual(sniffer.selected_iface(), 'ras:amir')
        self.assertEqual(sniffer._capture_filter, 'host 10.0.0.2')
        self.assertIsNone(sniffer._builder)
        self.assertEqual(sniffer._route_switches, 1)
        self.assertTrue(sniffer._running)
        self.assertEqual(sniffer._last_error, '')

    def test_disconnect_retry_and_flapping(self):
        sniffer, resolver = self.make_sniffer(None)
        self.assertEqual(sniffer._refresh_capture_target('Wi-Fi'), ('Wi-Fi', False))
        self.assertTrue(sniffer._route_warning)
        with patch.object(sniffer, '_capture_binding', side_effect=lambda value: (value, None)):
            for route in ('vpn', 'Wi-Fi', 'vpn'):
                resolver.return_value = route
                sniffer._refresh_capture_target('Wi-Fi')
            self.assertEqual(sniffer.selected_iface(), 'Wi-Fi')
            resolver.return_value = 'vpn'
            self.assertEqual(sniffer._refresh_capture_target('Wi-Fi'), ('vpn', True))
        self.assertEqual(sniffer._route_warning, '')

    def test_manual_adapter_is_not_overridden(self):
        sniffer, resolver = self.make_sniffer('ras:amir', manual=True)
        with patch.object(sniffer, '_capture_binding', return_value=('Wi-Fi', None)) as binding:
            self.assertEqual(sniffer._refresh_capture_target('Wi-Fi'), ('Wi-Fi', True))
        resolver.assert_not_called()
        binding.assert_called_once_with('Wi-Fi')
        self.assertEqual(sniffer._route_switches, 0)

    def test_ras_filter_updates_even_without_adapter_change(self):
        sniffer, resolver = self.make_sniffer('ras:amir')
        sniffer._iface = 'ras:amir'
        sniffer._capture_filter = 'host 10.0.0.1'
        with patch.object(sniffer, '_capture_binding', return_value=(['wan4', 'wan6'], 'host 10.0.0.2')):
            self.assertEqual(sniffer._refresh_capture_target('wan4'), (['wan4', 'wan6'], True))
        self.assertEqual(sniffer._capture_filter, 'host 10.0.0.2')

    def test_disappearing_capture_target_is_retried(self):
        sniffer, resolver = self.make_sniffer('vpn')
        with patch.object(sniffer, '_capture_binding', side_effect=ValueError('adapter unavailable')):
            self.assertEqual(sniffer._refresh_capture_target('Wi-Fi'), ('Wi-Fi', False))
            self.assertEqual(sniffer.selected_iface(), 'Wi-Fi')
            self.assertEqual(sniffer._refresh_capture_target('Wi-Fi'), ('Wi-Fi', False))
        self.assertEqual(sniffer.selected_iface(), 'Wi-Fi')
        self.assertTrue(sniffer._running)

    def test_loop_recovers_adapter_error_and_stop_remains_responsive(self):
        sniffer, resolver = self.make_sniffer('vpn')
        calls = []
        def sniff(**kwargs):
            calls.append(kwargs['iface'])
            if kwargs['iface'] != 'vpn':
                raise OSError('adapter gone')
            sniffer._stop_event.set()
        sniffer._sniff_func = sniff
        ticks = iter(range(0, 100, 3))
        with patch('core.netbotpro_sniffer_core.runtime.time.monotonic', side_effect=lambda: next(ticks)), \
                patch.object(sniffer, '_capture_binding', side_effect=lambda value: (value, None)):
            sniffer._sniff_loop('Wi-Fi')
        self.assertEqual(calls, ['Wi-Fi', 'vpn'])
        self.assertEqual(sniffer._last_error, '')
        self.assertFalse(sniffer._running)

    def test_auto_intent_preserved_at_start(self):
        for requested, expected in ((None, True), ('default', True), ('Wi-Fi', False)):
            sniffer, resolver = self.make_sniffer()
            sniffer._running = False
            sniffer._candidate_resolver = lambda value: value
            with patch.object(sniffer, '_capture_binding', return_value=('Wi-Fi', None)), \
                    patch.object(threading.Thread, 'start'):
                sniffer.start(requested)
            self.assertEqual(sniffer._auto_interface, expected)

