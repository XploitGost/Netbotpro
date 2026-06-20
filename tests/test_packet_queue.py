import queue
import unittest

from backend.app.services.packet_queue import BoundedPacketQueue


class BoundedPacketQueueTests(unittest.TestCase):
    def test_drop_newest_policy_rejects_overflow_packet(self):
        packet_queue = BoundedPacketQueue(max_size=2, overflow_policy="drop_newest")

        self.assertTrue(packet_queue.put({"id": "pkt-1"}))
        self.assertTrue(packet_queue.put({"id": "pkt-2"}))
        with self.assertLogs("backend.app.services.packet_queue", level="WARNING") as logs:
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
        self.assertEqual(stats["last_drop_reason"], "queue_full_drop_newest")
        self.assertEqual(stats["health"], "degraded")
        self.assertIn("dropping newest packet", "\n".join(logs.output))

    def test_drop_oldest_policy_keeps_newest_packet(self):
        packet_queue = BoundedPacketQueue(max_size=2, overflow_policy="drop_oldest")

        self.assertTrue(packet_queue.put({"id": "pkt-1"}))
        self.assertTrue(packet_queue.put({"id": "pkt-2"}))
        with self.assertLogs("backend.app.services.packet_queue", level="WARNING") as logs:
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
        self.assertEqual(stats["last_drop_reason"], "queue_full_drop_oldest")
        self.assertIn("dropping oldest packet", "\n".join(logs.output))

    def test_invalid_policy_defaults_to_drop_oldest(self):
        packet_queue = BoundedPacketQueue(max_size=1, overflow_policy="invalid")

        packet_queue.put({"id": "pkt-1"})
        packet_queue.put({"id": "pkt-2"})

        self.assertEqual(packet_queue.overflow_policy, "drop_oldest")
        self.assertEqual(packet_queue.get(timeout=0.01).packet["id"], "pkt-2")
        with self.assertRaises(queue.Empty):
            packet_queue.get(timeout=0.01)

    def test_stats_expose_clean_metric_names_and_worker_health(self):
        packet_queue = BoundedPacketQueue(max_size=4, overflow_policy="drop_oldest")

        packet_queue.put({"id": "pkt-1", "token": "secret-token"})
        packet_queue.put({"id": "pkt-2"})
        stats = packet_queue.stats(worker_alive=False)

        self.assertTrue(stats["enabled"])
        self.assertEqual(stats["max_size"], 4)
        self.assertEqual(stats["current_depth"], 2)
        self.assertEqual(stats["accepted_total"], 2)
        self.assertEqual(stats["dropped_total"], 0)
        self.assertEqual(stats["utilization_percent"], 50.0)
        self.assertFalse(stats["worker_alive"])
        self.assertEqual(stats["health"], "critical")
        self.assertNotIn("secret-token", str(stats))


if __name__ == "__main__":
    unittest.main()
