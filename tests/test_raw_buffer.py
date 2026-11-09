import threading
import time
import unittest
from unittest.mock import Mock

from core.netbotpro_sniffer_core.raw_buffer import RawBuffer
from core.netbotpro_sniffer_core.pcap_session import PcapBinding, DriverStats
from core.netbotpro_sniffer_core.runtime import NetSniffer


class Reader:
    pcap = 123
    wire_length = 54
    def __init__(self, count=20, fail=False):
        self.count, self.index, self.fail = count, 0, fail
        self.owners = set()
        self.closed = 0
    def setnonblock(self, enabled):
        assert enabled
    def next(self):
        self.owners.add(threading.get_ident())
        if self.fail:
            raise OSError('test')
        if self.index == self.count:
            return None, None
        self.index += 1
        return self.index, b'x'*16
    def close(self):
        self.owners.add(threading.get_ident())
        self.closed += 1


class RawBufferTests(unittest.TestCase):
    def test_raw_pressure_is_observable_and_affects_health(self):
        sniffer = NetSniffer(lambda packet: None)
        sniffer._running = True
        sniffer._thread = Mock()
        sniffer._thread.is_alive.return_value = True
        sniffer._pcap_binding = Mock()
        sniffer._pcap_binding.raw_status.return_value = [dict(queued_bytes=800, capacity_bytes=1000,
                                                             queued_frames=8, capacity_frames=10)]
        self.assertTrue(sniffer.capture_status()['raw_buffer_pressure'])
        self.assertEqual(sniffer.capture_status()['health'], 'degraded')

    def test_runtime_close_drains_after_stop_before_destroying_binding(self):
        buffer = RawBuffer(Reader(3), sampler=lambda handle: (3, 0, 0))
        deadline = time.monotonic() + 2
        while buffer.snapshot()['queued_frames'] < 3 and time.monotonic() < deadline:
            time.sleep(.005)
        class Socket:
            closed = False
            raw_reader = buffer
            def recv(self):
                return buffer.next()[0]
            def close(self):
                buffer.close()
                self.closed = True
        binding = PcapBinding('test', None, DriverStats(), factory=lambda *args: Socket(),
                              sampler=lambda socket: buffer.cached_stats())
        results = []
        sniffer = NetSniffer(results.append)
        sniffer._builder = Mock()
        sniffer._builder.build.side_effect = lambda packet: {'sequence': packet}
        sniffer._pcap_binding = binding
        sniffer._stop_event.set()
        sniffer._close_binding()
        self.assertEqual(results, [{'sequence': 1}, {'sequence': 2}, {'sequence': 3}])
        self.assertEqual(buffer.snapshot()['queued_frames'], 0)
        self.assertEqual(sniffer._last_raw_buffers[0]['high_water_frames'], 3)
        self.assertIsNone(sniffer._pcap_binding)

    def test_wire_timestamp_survives_processing_delay_and_custom_clock_wins(self):
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.dns import DNS, DNSQR
        from core.netbotpro_sniffer_core.packet_parser import PacketLayers, PacketMetadataBuilder
        class Process:
            def resolve(self, *args):
                return {}
        layers = PacketLayers(Ether, IP, TCP, UDP, ICMP, DNS, DNSQR)
        builder = PacketMetadataBuilder(layers, enable_geoip=False, enable_mac_vendor=False,
                                        process_mapper=Process())
        packet = Ether()/IP(src='192.0.2.1', dst='198.51.100.1')/TCP()
        packet.time = 1000.125
        self.assertEqual(builder.build(packet)['ts'], '1970-01-01T00:16:40.125+00:00')
        custom = PacketMetadataBuilder(layers, enable_geoip=False, enable_mac_vendor=False,
                                       process_mapper=Process(), timestamp_factory=lambda: 'custom')
        self.assertEqual(custom.build(packet)['ts'], 'custom')

    def test_bounded_fifo_backpressure_and_single_native_owner(self):
        reader = Reader()
        def sample(handle):
            reader.owners.add(threading.get_ident())
            return reader.index, 0, 0
        buffer = RawBuffer(reader, max_bytes=1024, max_frames=5,
                           max_frame_bytes=16, sampler=sample)
        received = []
        try:
            deadline = time.monotonic() + 2
            while buffer.snapshot()['queued_frames'] < 5 and time.monotonic() < deadline:
                time.sleep(.005)
            self.assertEqual(buffer.snapshot()['queued_frames'], 5)
            while len(received) < 20 and time.monotonic() < deadline:
                timestamp, data = buffer.next()
                if data is None:
                    time.sleep(.005)
                    continue
                received.append(timestamp)
                self.assertEqual(buffer.wire_length, 54)
                self.assertLessEqual(buffer.snapshot()['queued_bytes'], 1024)
        finally:
            buffer.close()
        self.assertEqual(received, list(range(1, 21)))
        self.assertEqual(reader.closed, 1)
        self.assertEqual(len(reader.owners), 1)
        self.assertNotIn(threading.get_ident(), reader.owners)
        self.assertEqual(buffer.cached_stats(), (20, 0, 0))
        buffer.close()
        self.assertEqual(reader.closed, 1)

    def test_stop_preserves_buffered_frames_for_drain(self):
        buffer = RawBuffer(Reader(3), sampler=lambda handle: (3, 0, 0))
        deadline = time.monotonic() + 2
        while buffer.snapshot()['queued_frames'] != 3 and time.monotonic() < deadline:
            time.sleep(.005)
        buffer.stop()
        self.assertEqual([buffer.next()[0] for _ in range(3)], [1, 2, 3])
        self.assertEqual(buffer.snapshot()['queued_bytes'], 0)
        self.assertEqual(buffer.next(), (None, None))

    def test_native_failure_is_explicit_not_empty_success(self):
        reader = Reader(fail=True)
        buffer = RawBuffer(reader, sampler=lambda handle: (0, 0, 0))
        buffer._thread.join(2)
        self.assertEqual(buffer.snapshot()['error'], 'OSError')
        with self.assertRaises(OSError):
            buffer.next()
        buffer.close()
        self.assertEqual(reader.closed, 1)

    def test_invalid_capacity_never_starts_native_reader(self):
        reader = Mock()
        with self.assertRaises(ValueError):
            RawBuffer(reader, max_bytes=10)
        reader.setnonblock.assert_not_called()
