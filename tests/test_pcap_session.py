import unittest
from unittest.mock import Mock, patch

from core.netbotpro_sniffer_core.pcap_session import DriverStats, PcapBinding, read_pcap_stats
from core.netbotpro_sniffer_core.runtime import NetSniffer


class FakeSocket:
    def __init__(self):
        self.closed = False
    def close(self):
        self.closed = True


class PcapStatsTests(unittest.TestCase):
    def test_running_without_an_open_handle_has_incomplete_coverage(self):
        sniffer = NetSniffer(lambda packet:None)
        sniffer._running = True
        sniffer._thread = Mock()
        sniffer._thread.is_alive.return_value = True
        sniffer._driver_stats = Mock()
        sniffer._driver_stats.snapshot.side_effect = lambda:dict(coverage_complete=True,
            active_handles=0, buffer_dropped_reported=0)
        self.assertFalse(sniffer.capture_status()['driver_stats']['coverage_complete'])
        sniffer._running = False
        self.assertTrue(sniffer.capture_status()['driver_stats']['coverage_complete'])

    def test_counter_reset_does_not_invent_billions_of_drops(self):
        stats = DriverStats()
        identifier = stats.register()
        stats.record(identifier, (100, 3, 0))
        stats.record(identifier, (110, 0, 0))
        self.assertEqual(stats.snapshot()['buffer_dropped_reported'], 3)
        self.assertEqual(stats.snapshot()['received_reported'], 110)
        self.assertFalse(stats.snapshot()['coverage_complete'])
        self.assertEqual(stats.snapshot()['counter_resets'], 1)

    def test_unknown_is_not_zero_and_counter_wrap_is_accumulated(self):
        stats = DriverStats()
        self.assertIsNone(stats.snapshot()['buffer_dropped_reported'])
        identifier = stats.register()
        stats.record(identifier, ((1 << 32)-1, 3, 0))
        stats.record(identifier, (2, 5, 0))
        result = stats.snapshot()
        self.assertEqual(result['received_reported'], (1 << 32)+2)
        self.assertEqual(result['buffer_dropped_reported'], 5)
        self.assertEqual(result['interface_drop_support'], 'unknown')
        self.assertTrue(result['coverage_complete'])

    def test_multiple_handles_and_final_read_failure_preserve_uncertainty(self):
        stats = DriverStats()
        first = stats.register()
        stats.record(first, (10, 2, 0))
        stats.retire(first)
        second = stats.register()
        stats.record(second, (5, 1, 0))
        stats.record(second, None)
        stats.retire(second)
        result = stats.snapshot()
        self.assertEqual(result['buffer_dropped_reported'], 3)
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['uncovered_closed_handles'], 1)

    def test_persistent_multi_socket_binding_and_partial_open_cleanup(self):
        stats = DriverStats()
        sockets = []
        def factory(device, capture_filter):
            socket = FakeSocket()
            sockets.append(socket)
            return socket
        binding = PcapBinding(['wan4', 'wan6'], 'host 192.0.2.1', stats,
                              factory=factory, sampler=lambda socket: (10, 0, 0))
        self.assertEqual(len(binding.sniff_arguments()['opened_socket']), 2)
        self.assertTrue(binding.matches(['wan4', 'wan6'], 'host 192.0.2.1'))
        self.assertFalse(binding.matches(['wan4', 'wan6'], 'host 192.0.2.2'))
        binding.sample()
        binding.close()
        binding.close()
        self.assertTrue(all(socket.closed for socket in sockets))
        self.assertEqual(stats.snapshot()['received_reported'], 20)
        self.assertEqual(stats.snapshot()['active_handles'], 0)
        socket = FakeSocket()
        factory = Mock(side_effect=[socket, ValueError('missing IPv6 adapter')])
        with self.assertRaises(ValueError):
            PcapBinding(['wan4', 'wan6'], None, stats, factory=factory,
                        sampler=lambda socket: (0, 0, 0))
        self.assertTrue(socket.closed)
        self.assertEqual(stats.snapshot()['active_handles'], 0)

    def test_no_native_call_on_closed_socket(self):
        socket = FakeSocket()
        socket.closed = True
        with self.assertRaisesRegex(ValueError, 'closed'):
            read_pcap_stats(socket)

    def test_runtime_reuses_owned_socket_across_sniff_polls(self):
        sniffer = NetSniffer(lambda packet: None)
        sniffer._running = True
        calls = []
        def sniff(**kwargs):
            calls.append(kwargs)
            if len(calls) == 3:
                sniffer._stop_event.set()
        sniff.__module__ = 'scapy.sendrecv'
        sniffer._sniff_func = sniff
        binding = Mock()
        binding.matches.return_value = True
        binding.is_closed.return_value = False
        binding.sniff_arguments.return_value = {'opened_socket': {'socket': 'test'}}
        order = []
        def prepare():
            order.append('prepare')
        def open_binding(*args):
            order.append('open')
            return binding
        with patch.object(sniffer, '_packet_builder', side_effect=prepare), \
                patch('core.netbotpro_sniffer_core.runtime.PcapBinding', side_effect=open_binding) as create:
            sniffer._sniff_loop('test')
        self.assertEqual(len(calls), 3)
        self.assertEqual(order, ['prepare', 'open'])
        create.assert_called_once()
        binding.close.assert_called_once()
        for call in calls:
            self.assertIn('opened_socket', call)
            self.assertNotIn('iface', call)

    def test_builder_failure_never_activates_capture_handle(self):
        sniffer = NetSniffer(lambda packet: None)
        sniffer._running = True
        sniff = Mock()
        sniff.__module__ = 'scapy.sendrecv'
        sniffer._sniff_func = sniff
        with patch.object(sniffer, '_packet_builder', side_effect=RuntimeError('setup failed')), \
                patch('core.netbotpro_sniffer_core.runtime.PcapBinding') as create, \
                self.assertLogs('core.netbotpro_sniffer_core.runtime', level='ERROR'):
            sniffer._sniff_loop('test')
        create.assert_not_called()
        sniff.assert_not_called()
        self.assertFalse(sniffer._running)
        self.assertIn('setup failed', sniffer._last_error)
