import unittest
from unittest.mock import patch
from backend.app.services.event_bus import EventBus


class WebsocketLatencyWindowTests(unittest.TestCase):
    def test_old_latency_expires_without_new_messages(self):
        bus = EventBus()
        try:
            with patch('backend.app.services.event_bus.time.monotonic', return_value=100), patch('backend.app.services.event_bus.time.perf_counter', return_value=1):
                bus.record_send_latency(0.5)
                self.assertEqual(bus.websocket_stats()['health'], 'degraded')
            with patch('backend.app.services.event_bus.time.monotonic', return_value=161):
                stats = bus.websocket_stats()
                self.assertEqual(stats['send_latency_ms_p95'], 0)
                self.assertEqual(stats['health'], 'healthy')
        finally:
            bus.close()
