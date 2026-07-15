import asyncio
import time
import unittest

from backend.app.services.event_aggregator import EventAggregator
from backend.app.services.event_bus import EventBus


class EventAggregatorTests(unittest.TestCase):
    def test_batches_packet_events_when_max_size_is_reached(self):
        emitted = []
        aggregator = EventAggregator(
            emitted.append,
            packet_batch_ms=10000,
            packet_batch_max=2,
        )

        aggregator.publish("packet:new", {"id": "pkt-1"})
        aggregator.publish("packet:new", {"id": "pkt-2"})

        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["type"], "packet_batch")
        self.assertEqual(emitted[0]["count"], 2)
        self.assertEqual(emitted[0]["events"][0]["payload"]["id"], "pkt-1")

    def test_batches_alert_events_and_redacts_payloads(self):
        emitted = []
        aggregator = EventAggregator(
            emitted.append,
            alert_batch_ms=10000,
            alert_batch_max=1,
        )

        aggregator.publish(
            "alert:new",
            {"id": "alert-1", "detail": "Authorization: Bearer alert-secret"},
        )

        self.assertEqual(emitted[0]["type"], "alert_batch")
        rendered = str(emitted[0])
        self.assertNotIn("alert-secret", rendered)
        self.assertIn("[redacted", rendered.lower())

    def test_coalesces_dashboard_summary_events(self):
        emitted = []
        aggregator = EventAggregator(emitted.append, summary_batch_ms=10000)

        aggregator.publish("dashboard:summary", {"packet_count": 1})
        aggregator.publish("dashboard:summary", {"packet_count": 2})
        aggregator.flush_all()

        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["type"], "dashboard_summary")
        self.assertEqual(emitted[0]["summary"]["packet_count"], 2)
        self.assertEqual(aggregator.stats()["events_coalesced_total"], 1)

    def test_batches_flow_events_as_delta_updates(self):
        emitted = []
        aggregator = EventAggregator(
            emitted.append,
            flow_batch_ms=10000,
            flow_batch_max=2,
        )

        aggregator.publish("flow:updated", {"flow_id": "flow-1"})
        aggregator.publish("flow:updated", {"flow_id": "flow-2"})

        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["type"], "flow_delta")
        self.assertEqual(emitted[0]["count"], 2)
        self.assertEqual(emitted[0]["updates"][0]["payload"]["flow_id"], "flow-1")

    def test_batches_and_redacts_incident_updates(self):
        emitted = []
        aggregator = EventAggregator(
            emitted.append, alert_batch_ms=10000, alert_batch_max=1
        )
        aggregator.publish(
            "incident:update", {"incident_id": "inc-1", "evidence": "token=raw-secret"}
        )
        self.assertEqual(emitted[0]["type"], "incident_batch")
        self.assertNotIn("raw-secret", str(emitted[0]))
        self.assertEqual(aggregator.stats()["pending_incident_events"], 0)

    def test_batch_interval_triggers_flush(self):
        emitted = []
        aggregator = EventAggregator(
            emitted.append,
            packet_batch_ms=20,
            packet_batch_max=100,
        )

        aggregator.publish("packet:new", {"id": "pkt-1"})
        deadline = time.monotonic() + 1.0
        while not emitted and time.monotonic() < deadline:
            time.sleep(0.01)

        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["type"], "packet_batch")
        aggregator.close()

    def test_metrics_track_drops_and_health(self):
        aggregator = EventAggregator(lambda _message: None)

        aggregator.record_dropped(reason="client_queue_full_drop_newest")
        stats = aggregator.stats()

        self.assertEqual(stats["events_dropped_total"], 1)
        self.assertEqual(stats["last_drop_reason"], "client_queue_full_drop_newest")
        self.assertEqual(stats["health"], "degraded")

    def test_close_flushes_pending_events_and_cancels_timers(self):
        emitted = []
        aggregator = EventAggregator(
            emitted.append,
            packet_batch_ms=10000,
            packet_batch_max=100,
        )

        aggregator.publish("packet:new", {"id": "pkt-close"})
        aggregator.close()

        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["type"], "packet_batch")
        self.assertEqual(aggregator.stats()["pending_packet_events"], 0)


class EventBusSlowClientTests(unittest.TestCase):
    def _fill_slow_client(self, policy: str):
        bus = EventBus()
        bus._aggregator.client_queue_max = 2
        bus._aggregator.slow_client_policy = policy
        queue = bus.subscribe()

        for index in range(5):
            bus._publish_direct(
                {"version": 1, "type": "manual", "payload": {"i": index}}
            )

        return bus, queue

    def test_drop_oldest_policy_does_not_grow_queue_unbounded(self):
        bus, queue = self._fill_slow_client("drop_oldest")

        self.assertLessEqual(queue.qsize(), 2)
        stats = bus.websocket_stats()
        self.assertEqual(stats["client_queue_depth_max"], 2)
        self.assertGreater(stats["dropped_for_slow_client_total"], 0)
        self.assertEqual(stats["health"], "critical")
        self.assertEqual(stats["last_drop_reason"], "client_queue_full_drop_oldest")
        items = [queue.get_nowait()["payload"]["i"] for _ in range(queue.qsize())]
        self.assertEqual(items, [3, 4])

    def test_drop_newest_policy_preserves_existing_queue(self):
        bus, queue = self._fill_slow_client("drop_newest")

        self.assertLessEqual(queue.qsize(), 2)
        items = [queue.get_nowait()["payload"]["i"] for _ in range(queue.qsize())]
        self.assertEqual(items, [0, 1])
        stats = bus.websocket_stats()
        self.assertGreater(stats["dropped_for_slow_client_total"], 0)
        self.assertEqual(stats["last_drop_reason"], "client_queue_full_drop_newest")

    def test_coalesce_policy_keeps_latest_message_and_counts_coalescing(self):
        bus, queue = self._fill_slow_client("coalesce")

        self.assertLessEqual(queue.qsize(), 2)
        items = [queue.get_nowait()["payload"]["i"] for _ in range(queue.qsize())]
        self.assertEqual(items, [3, 4])
        stats = bus.websocket_stats()
        self.assertGreater(stats["coalesced_for_slow_client_total"], 0)
        self.assertEqual(stats["last_drop_reason"], "client_queue_full_coalesce")

    def test_websocket_send_latency_metrics(self):
        bus = EventBus()
        started = time.perf_counter() - 0.3

        bus.record_send_latency(started, ok=True)
        stats = bus.websocket_stats()

        self.assertGreaterEqual(stats["send_latency_ms_avg"], 250)
        self.assertGreaterEqual(stats["websocket_send_latency_ms_avg"], 250)
        self.assertGreaterEqual(stats["send_latency_ms_p95"], 250)
        self.assertIn("websocket_send_latency", stats["pressure_reasons"])

    def test_existing_envelope_shape_is_preserved_for_non_batched_events(self):
        bus = EventBus()
        queue = bus.subscribe()
        bus.publish("hello:test", {"ok": True})
        message = queue.get_nowait()

        self.assertEqual(message["version"], 1)
        self.assertEqual(message["type"], "hello:test")
        self.assertEqual(message["payload"]["ok"], True)


if __name__ == "__main__":
    unittest.main()
