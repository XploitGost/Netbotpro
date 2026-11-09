import ctypes
import random
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from core.netbotpro_sniffer_core.pcap_reader import PcapByteReader, CaptureSocket, attach_fast_reader


class Timeval(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long), ('tv_usec', ctypes.c_long)]


class Header(ctypes.Structure):
    _fields_ = [('ts', Timeval), ('caplen', ctypes.c_uint), ('len', ctypes.c_uint)]


def descriptor(data, wire_length=None):
    memory = (ctypes.c_ubyte * max(1, len(data)))(*data)
    header = Header(Timeval(10, 125000), len(data), len(data) if wire_length is None else wire_length)
    return SimpleNamespace(pcap=object(), header=ctypes.pointer(header),
        pkt_data=ctypes.cast(memory, ctypes.POINTER(ctypes.c_ubyte)), remaining=True,
        memory=memory, close=Mock())


class PcapReaderTests(unittest.TestCase):
    def test_bytes_match_original_and_timestamp_is_preserved(self):
        randomizer = random.Random(47)
        for length in (0, 1, 60, 1500, 9000):
            data = bytes(randomizer.randrange(256) for _ in range(length))
            fd = descriptor(data)
            original = bytes(bytearray(fd.pkt_data[:length]))
            reader = PcapByteReader(fd, lambda *args:1)
            timestamp, packet = reader.next()
            self.assertEqual(packet, original)
            self.assertEqual(timestamp, 10.125)
            self.assertEqual(reader.wire_length, length)
            self.assertTrue(fd.remaining)

    def test_truncated_frame_copies_only_caplen_and_exposes_original_length(self):
        fd = descriptor(b'captured', wire_length=1500)
        reader = PcapByteReader(fd, lambda *args:1)
        self.assertEqual(reader.next()[1], b'captured')
        original = Mock()
        original.pcap_fd = reader
        original.recv.return_value = SimpleNamespace()
        packet = CaptureSocket(original).recv()
        self.assertEqual(packet.wirelen, 1500)

    def test_timeout_failure_eof_invalid_length_and_close(self):
        fd = descriptor(b'test')
        status = [0]
        reader = PcapByteReader(fd, lambda *args:status[0])
        self.assertEqual(reader.next(), (None, None))
        self.assertFalse(fd.remaining)
        status[0] = -1
        with self.assertRaises(OSError):
            reader.next()
        status[0] = -2
        with self.assertRaises(EOFError):
            reader.next()
        status[0] = 1
        fd.header.contents.caplen = 2000
        with self.assertRaises(ValueError):
            reader.next()
        reader.close()
        reader.close()
        fd.close.assert_called_once()
        with self.assertRaises(EOFError):
            reader.next()

    def test_unsupported_socket_and_disabled_path_keep_scapy(self):
        socket = SimpleNamespace()
        self.assertIs(attach_fast_reader(socket), socket)
        with patch.dict('os.environ', NETBOT_FAST_PCAP_COPY='0'):
            self.assertIs(attach_fast_reader(socket), socket)
