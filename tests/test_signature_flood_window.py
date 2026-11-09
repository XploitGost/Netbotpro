import unittest
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from core.ids_signature import SignatureIDS


class FloodWindowTests(unittest.TestCase):
    def test_throttled_global_cleanup_preserves_exact_source_window(self):
        detector = SignatureIDS()
        detector.flood_threshold = 2
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        meta = {'src':'192.0.2.1', 'proto':'ICMP'}
        with patch('core.ids_signature.datetime') as clock:
            with patch.object(detector, '_cleanup', wraps=detector._cleanup) as cleanup:
                for offset in (0, 0.1, 2.9, 3.05):
                    clock.now.return_value = now + timedelta(seconds=offset)
                    detector.analyze_packet(meta)
                self.assertEqual(cleanup.call_count, 2)
                self.assertEqual(len(detector.flood_counter[meta['src']]), 3)

    def test_concurrent_cleanup_and_analysis_preserve_all_packets(self):
        detector = SignatureIDS()
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expired = now - timedelta(seconds=100)
        key = ('192.0.2.1', '192.0.2.2')
        detector.port_scan_map[key] = [(expired, 80)]
        detector.syn_counter[key] = [expired]
        detector.flood_threshold = 100000
        detector.port_scan_threshold = 100000
        detector.syn_threshold = 100000
        barrier = threading.Barrier(4)
        def analyze():
            barrier.wait(timeout=5)
            for _ in range(150):
                detector.analyze_packet(dict(src=key[0], dst=key[1], proto='TCP', dport=80, flags='S'))
        with patch('core.ids_signature.datetime') as clock:
            clock.now.return_value = now
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = [pool.submit(analyze) for _ in range(4)]
                for future in futures:
                    future.result(timeout=15)
        self.assertEqual(len(detector.flood_counter[key[0]]), 600)
        self.assertEqual(len(detector.port_scan_map[key]), 600)
        self.assertEqual(len(detector.syn_counter[key]), 600)

    def test_analysis_holds_lock_during_cleanup_and_releases_after_error(self):
        detector = SignatureIDS()
        owned = []
        def failing_cleanup(now):
            owned.append(detector._state_lock._is_owned())
            raise ValueError('test failure')
        with patch.object(detector, '_cleanup', side_effect=failing_cleanup):
            with self.assertRaises(ValueError):
                detector.analyze_packet({'src':'192.0.2.1', 'proto':'ICMP'})
        self.assertEqual(owned, [True])
        with ThreadPoolExecutor(max_workers=1) as pool:
            self.assertIsNone(pool.submit(detector.analyze_packet, {'src':'192.0.2.1', 'proto':'ICMP'}).result(timeout=5))

    def test_exact_boundary_and_expiry_preserve_counts(self):
        detector = SignatureIDS()
        detector.flood_threshold = 2
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        packet = {'src': '192.0.2.1', 'proto': 'ICMP'}
        with patch('core.ids_signature.datetime') as clock:
            clock.now.return_value = now
            self.assertIsNone(detector.analyze_packet(packet))
            clock.now.return_value = now + timedelta(seconds=3)
            self.assertEqual(detector.analyze_packet(packet)['score'], 2)
            clock.now.return_value = now + timedelta(seconds=6, microseconds=1)
            self.assertIsNone(detector.analyze_packet(packet))
        self.assertEqual(len(detector.flood_counter[packet['src']]), 1)

    def test_backward_clock_keeps_window_ordered(self):
        detector = SignatureIDS()
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with patch('core.ids_signature.datetime') as clock:
            for offset in (2, 0, 1):
                clock.now.return_value = now + timedelta(seconds=offset)
                detector.analyze_packet({'src':'192.0.2.1','proto':'ICMP'})
        values = list(detector.flood_counter['192.0.2.1'])
        self.assertEqual(values, sorted(values))
