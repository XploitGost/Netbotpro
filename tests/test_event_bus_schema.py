import unittest

from backend.app.services.event_bus import EventBus


class EventBusSchemaTests(unittest.TestCase):
    def test_publish_wraps_payload_in_versioned_envelope(self):
        bus = EventBus()
        queue = bus.subscribe()
        bus.publish("packet:new", {"src": "1.1.1.1"})
        message = queue.get_nowait()
        self.assertEqual(message["version"], 1)
        self.assertEqual(message["type"], "packet:new")
        self.assertIn("timestamp", message)
        self.assertEqual(message["payload"]["src"], "1.1.1.1")


if __name__ == "__main__":
    unittest.main()
