import unittest

from backend.app.services.sniffer_event_publisher import SnifferEventPublisher


class DummyBus:
    def __init__(self):
        self.events = []

    def publish(self, event_type, payload):
        self.events.append((event_type, payload))


class SnifferEventPublisherTests(unittest.TestCase):
    def test_publish_packet_and_alerts(self):
        bus = DummyBus()
        publisher = SnifferEventPublisher(bus)

        publisher.publish_packet({"src": "1.1.1.1"})
        publisher.publish_alerts([{"attack_type": "scan"}, {"attack_type": "dos"}])
        publisher.publish_state("sniffer:started", {"running": True})

        self.assertEqual(
            bus.events,
            [
                ("packet:new", {"src": "1.1.1.1"}),
                ("alert:new", {"attack_type": "scan"}),
                ("alert:new", {"attack_type": "dos"}),
                ("sniffer:started", {"running": True}),
            ],
        )


if __name__ == "__main__":
    unittest.main()
