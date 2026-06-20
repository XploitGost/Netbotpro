import queue
import unittest

from backend.app.services.packet_queue import BoundedPacketQueue


class BoundedPacketQueueTests(unittest.TestCase):
    def test_drop_newest_policy_rejects_overflow_packet(self):
        packet_queue = BoundedPacketQueue(max_size=2, overflow_policy="drop_newest")

        self.assertTrue(packet_queue.put({"id": "pkt-1"}))
        self.assertTrue(packet_queue.put({"id": "pkt-2"}))
        self.assertFalse(packet_queue.put({"id": "pkt-3"}))

        first = packet_queue.get(timeout=0.01).packet
        second = packet_queue.get(timeout=0.01).packet
        stats = packet_queue.stats()

        self.assertEqual(first["id"], "pkt-1")
        self.assertEqual(second["id"], "pkt-2")
        self.assertEqual(stats["queue_high_water_mark"], 2)
        self.assertEqual(stats["accepted_packets"], 2)
        self.assertEqual(stats["dropped_packets"], 1)
        self.assertEqual(stats["dropped_newest"], 1)

    def test_drop_oldest_policy_keeps_newest_packet(self):
        packet_queue = BoundedPacketQueue(max_size=2, overflow_policy="drop_oldest")

        self.assertTrue(packet_queue.put({"id": "pkt-1"}))
        self.assertTrue(packet_queue.put({"id": "pkt-2"}))
        self.assertTrue(packet_queue.put({"id": "pkt-3"}))

        first = packet_queue.get(timeout=0.01).packet
        second = packet_queue.get(timeout=0.01).packet
        stats = packet_queue.stats()

        self.assertEqual(first["id"], "pkt-2")
        self.assertEqual(second["id"], "pkt-3")
        self.assertEqual(stats["queue_high_water_mark"], 2)
        self.assertEqual(stats["accepted_packets"], 3)
        self.assertEqual(stats["dropped_packets"], 1)
        self.assertEqual(stats["dropped_oldest"], 1)

    def test_invalid_policy_defaults_to_drop_oldest(self):
        packet_queue = BoundedPacketQueue(max_size=1, overflow_policy="invalid")

        packet_queue.put({"id": "pkt-1"})
        packet_queue.put({"id": "pkt-2"})

        self.assertEqual(packet_queue.overflow_policy, "drop_oldest")
        self.assertEqual(packet_queue.get(timeout=0.01).packet["id"], "pkt-2")
        with self.assertRaises(queue.Empty):
            packet_queue.get(timeout=0.01)


if __name__ == "__main__":
    unittest.main()
