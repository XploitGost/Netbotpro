import threading
import time
import unittest
from unittest.mock import Mock, patch

from core.netbotpro_sniffer_core.route_probe import RouteProbe
from core.netbotpro_sniffer_core.runtime import NetSniffer
from core.netbotpro_sniffer_core import interfaces


class RouteProbeTests(unittest.TestCase):
    def test_adapter_registry_reload_is_serialized(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def enumerate_interfaces():
            calls.append(1)
            entered.set()
            release.wait(2)
            return []
        threads = [threading.Thread(target=interfaces._scapy_interfaces) for _ in range(2)]
        with patch.object(interfaces, '_enumerate_scapy_interfaces', side_effect=enumerate_interfaces):
            try:
                threads[0].start()
                self.assertTrue(entered.wait(1))
                threads[1].start()
                time.sleep(.03)
                self.assertEqual(len(calls), 1)
            finally:
                release.set()
                for thread in threads:
                    if thread.ident is not None:
                        thread.join(2)
        self.assertEqual(len(calls), 2)
        self.assertFalse(any(thread.is_alive() for thread in threads))

    def test_blocked_discovery_does_not_block_capture_or_spawn_more_probes(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def observe():
            calls.append(threading.current_thread().name)
            entered.set()
            release.wait(2)
            return 'wifi', 'wifi', None, ''
        sniffer = NetSniffer(lambda packet: None)
        sniffer._running = True
        packets_during_probe = []
        def sniff(**kwargs):
            self.assertTrue(entered.wait(1))
            packets_during_probe.extend(range(128))
            sniffer._stop_event.set()
        sniff.__module__ = 'scapy.sendrecv'
        sniffer._sniff_func = sniff
        binding = Mock()
        binding.sniff_arguments.return_value = {'opened_socket': {}}
        binding.is_closed.return_value = False
        probe = RouteProbe(observe, interval=.01)
        try:
            with patch('core.netbotpro_sniffer_core.runtime.RouteProbe', return_value=probe), \
                    patch('core.netbotpro_sniffer_core.runtime.PcapBinding', return_value=binding), \
                    patch.object(sniffer, '_packet_builder'):
                sniffer._sniff_loop('wifi')
            self.assertEqual(len(packets_during_probe), 128)
            self.assertEqual(calls, ['capture-route-probe'])
            self.assertIsNone(probe.take())
        finally:
            release.set()
            probe.close()
        self.assertIsNone(probe.take())

    def test_only_latest_completed_result_is_retained_and_consumed_once(self):
        completed = threading.Event()
        calls = []
        def observe():
            calls.append(len(calls) + 1)
            if len(calls) >= 4:
                completed.set()
            return calls[-1]
        probe = RouteProbe(observe, interval=.01)
        try:
            self.assertTrue(completed.wait(1))
        finally:
            probe.close()
        result = probe.take()
        self.assertEqual(result, calls[-1])
        self.assertIsNone(probe.take())
        count = len(calls)
        time.sleep(.03)
        self.assertEqual(len(calls), count)

    def test_discovery_does_not_mutate_capture_selection_before_apply(self):
        sniffer = NetSniffer(lambda packet: None, iface_resolver=lambda: 'vpn')
        sniffer._iface = 'wifi'
        builder = sniffer._builder = object()
        with patch.object(sniffer, '_capture_binding', return_value=('wan', 'host 10.0.0.1')):
            result = sniffer._observe_capture_target()
        self.assertEqual(sniffer.selected_iface(), 'wifi')
        self.assertIs(sniffer._builder, builder)
        self.assertEqual(result, ('vpn', 'wan', 'host 10.0.0.1', ''))
