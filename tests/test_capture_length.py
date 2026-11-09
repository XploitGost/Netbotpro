import unittest
from core.netbotpro_sniffer_core.packet_parser import captured_packet_length


class CaptureLengthTests(unittest.TestCase):
    def test_capture_length_does_not_serialize_packet(self):
        class Frame:
            wirelen = 1514
            def __len__(self):
                raise AssertionError('Scapy serialization should not run')
        self.assertEqual(captured_packet_length(Frame()), 1514)

    def test_missing_or_invalid_capture_length_falls_back(self):
        class Frame:
            def __len__(self):
                return 54
        for value in (None, 0, -1, '1514', True):
            frame = Frame()
            frame.wirelen = value
            self.assertEqual(captured_packet_length(frame), 54)
        self.assertEqual(captured_packet_length(Frame()), 54)
