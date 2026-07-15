from __future__ import annotations

import json
import os
import threading
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.main import app, sniffer_service
from backend.app.security import require_local_token, require_trusted_client
from backend.app.services.live_ring_buffer import (
    DEFAULT_CAPACITIES,
    LiveRingBuffer,
)
from backend.app.services.monitoring_service import build_monitoring_metrics


class LiveRingBufferTests(unittest.TestCase):
    def make_buffer(self, **overrides):
        capacities = {category: 3 for category in DEFAULT_CAPACITIES}
        capacities.update(overrides.pop("capacities", {}))
        return LiveRingBuffer(capacities=capacities, **overrides)

    def test_creates_all_category_buffers_with_configured_capacity(self):
        ring = self.make_buffer(capacities={"packet": 2, "flow": 4})

        metrics = ring.metrics()

        self.assertEqual(metrics["categories"]["packet"]["capacity"], 2)
        self.assertEqual(metrics["categories"]["flow"]["capacity"], 4)
        self.assertEqual(len(metrics["categories"]), 7)

    def test_appends_supported_live_records(self):
        ring = self.make_buffer()

        for category in ("packet", "flow", "alert", "expert_info"):
            ring.append(category, {"id": category}, flow_key="flow-1")

        self.assertEqual(ring.metrics()["total_records"], 4)
        self.assertEqual(ring.query("flow")["items"][0]["flow_key"], "flow-1")

    def test_evicts_oldest_and_tracks_counter(self):
        ring = self.make_buffer(capacities={"packet": 2})
        ring.append("packet", {"id": 1})
        ring.append("packet", {"id": 2})
        ring.append("packet", {"id": 3})

        items = ring.query("packet", limit=10)["items"]
        metrics = ring.metrics()

        self.assertEqual([item["payload"]["id"] for item in items], [3, 2])
        self.assertEqual(metrics["records_evicted_total"], 1)
        self.assertEqual(metrics["categories"]["packet"]["evicted_total"], 1)

    def test_query_by_type_flow_key_since_and_latest_order(self):
        ring = self.make_buffer()
        ring.append(
            "packet",
            {"id": "old"},
            flow_key="flow-a",
            timestamp="2026-01-01T00:00:00Z",
        )
        ring.append(
            "packet",
            {"id": "new"},
            flow_key="flow-a",
            timestamp="2026-01-02T00:00:00Z",
        )
        ring.append("packet", {"id": "other"}, flow_key="flow-b")

        result = ring.query(
            "packet",
            flow_key="flow-a",
            since="2026-01-01T12:00:00Z",
        )

        self.assertEqual([item["payload"]["id"] for item in result["items"]], ["new"])

    def test_query_limit_is_capped_and_visible(self):
        ring = self.make_buffer(default_query_limit=2, max_query_limit=2)
        for index in range(3):
            ring.append("packet", {"id": index})

        result = ring.query("packet", limit=999)

        self.assertEqual(result["limit"], 2)
        self.assertTrue(result["truncated"])
        self.assertEqual(ring.metrics()["query_limit_rejected_total"], 1)
        self.assertIn(
            "live_ring_query_limit_rejections",
            ring.metrics()["pressure_reasons"],
        )

    def test_disabled_ring_does_not_store_records(self):
        ring = self.make_buffer(enabled=False)

        self.assertIsNone(ring.append("packet", {"id": 1}))
        self.assertEqual(ring.metrics()["total_records"], 0)

    def test_ttl_prunes_expired_records(self):
        ring = self.make_buffer(ttl_seconds=60)
        ring.append("packet", {"id": "expired"}, timestamp="2020-01-01T00:00:00Z")

        self.assertEqual(ring.query("packet")["items"], [])
        self.assertEqual(ring.metrics()["records_evicted_total"], 1)

    def test_invalid_env_values_fall_back_to_safe_defaults(self):
        with patch.dict(
            os.environ,
            {
                "NETBOT_LIVE_RING_PACKET_MAX": "unlimited",
                "NETBOT_LIVE_RING_DEFAULT_QUERY_LIMIT": "bad",
                "NETBOT_LIVE_RING_MAX_QUERY_LIMIT": "0",
                "NETBOT_LIVE_RING_TTL_SECONDS": "-1",
            },
            clear=False,
        ):
            ring = LiveRingBuffer.from_env()

        self.assertEqual(ring.capacities["packet"], 5000)
        self.assertEqual(ring.default_query_limit, 250)
        self.assertEqual(ring.max_query_limit, 2000)
        self.assertEqual(ring.ttl_seconds, 0)

    def test_records_are_redacted_and_raw_payload_fields_removed(self):
        ring = self.make_buffer()
        secret = "ring-secret-value"

        ring.append(
            "packet",
            {
                "authorization": f"Bearer {secret}",
                "cookie": f"session={secret}",
                "path": f"/login?token={secret}",
                "payload_ascii": secret,
                "nested": {"password": secret},
            },
        )

        serialized = json.dumps(ring.query("packet"))
        self.assertNotIn(secret, serialized)
        self.assertIn("[REDACTED]", serialized)
        self.assertEqual(
            ring.query("packet")["items"][0]["payload"]["payload_ascii"], ""
        )

    def test_metrics_never_expose_payload_values(self):
        ring = self.make_buffer()
        ring.append("alert", {"secret": "do-not-leak"})

        serialized = json.dumps(ring.metrics())

        self.assertNotIn("do-not-leak", serialized)
        self.assertNotIn("payload", serialized)

    def test_health_transitions_for_utilization_evictions_and_errors(self):
        ring = self.make_buffer(capacities={"packet": 2})
        self.assertEqual(ring.metrics()["health"], "healthy")

        ring.append("packet", {"id": 1})
        ring.append("packet", {"id": 2})
        self.assertEqual(ring.metrics()["health"], "degraded")
        self.assertIn("live_ring_high_utilization", ring.metrics()["pressure_reasons"])

        self.assertIsNone(ring.append("unsupported", {}))
        self.assertEqual(ring.metrics()["health"], "critical")
        self.assertEqual(ring.metrics()["last_error"], "UnsupportedCategory")

    def test_concurrent_append_and_query_is_safe(self):
        ring = self.make_buffer(capacities={"packet": 50})
        errors = []

        def writer(offset):
            try:
                for index in range(200):
                    ring.append("packet", {"id": offset + index})
            except Exception as exc:  # pragma: no cover - assertion capture
                errors.append(exc)

        def reader():
            try:
                for _ in range(200):
                    ring.query("packet", limit=20)
            except Exception as exc:  # pragma: no cover - assertion capture
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i * 1000,)) for i in range(3)]
        threads.append(threading.Thread(target=reader))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertLessEqual(ring.metrics()["categories"]["packet"]["records"], 50)

    def test_clear_and_reset(self):
        ring = self.make_buffer(capacities={"packet": 1})
        ring.append("packet", {"id": 1})
        ring.append("packet", {"id": 2})
        ring.clear()
        self.assertEqual(ring.metrics()["total_records"], 0)
        self.assertEqual(ring.metrics()["records_evicted_total"], 1)

        ring.reset()
        self.assertEqual(ring.metrics()["records_evicted_total"], 0)
        self.assertEqual(ring.metrics()["records_added_total"], 0)


class LiveRingMonitoringTests(unittest.TestCase):
    def test_monitoring_metrics_include_ring_and_pressure(self):
        metrics = build_monitoring_metrics(
            sniffer_state={},
            observability={
                "live_ring_buffer": {
                    "enabled": True,
                    "health": "degraded",
                    "total_records": 9,
                    "total_capacity": 10,
                    "utilization_percent": 90,
                    "records_added_total": 12,
                    "records_evicted_total": 2,
                    "records_dropped_total": 0,
                    "query_count_total": 4,
                    "query_limit_rejected_total": 1,
                    "last_added_at": "2026-01-01T00:00:00+00:00",
                    "last_evicted_at": "2026-01-01T00:00:01+00:00",
                    "last_error": "",
                    "categories": {
                        "packet": {
                            "records": 9,
                            "capacity": 10,
                            "utilization_percent": 90,
                            "evicted_total": 2,
                        }
                    },
                    "pressure_reasons": ["live_ring_high_utilization"],
                }
            },
            flow_summary={},
        )

        ring = metrics["live_ring_buffer"]
        self.assertEqual(ring["total_records"], 9)
        self.assertEqual(ring["categories"]["packet"]["capacity"], 10)
        self.assertIn("live_ring_high_utilization", metrics["pressure_reasons"])
        self.assertEqual(metrics["health"], "degraded")


class LiveRingApiTests(unittest.TestCase):
    def setUp(self):
        app.dependency_overrides[require_trusted_client] = lambda: None
        app.dependency_overrides[require_local_token] = lambda: None
        self.client = TestClient(app)
        self.original_ring = sniffer_service._live_ring_buffer
        sniffer_service._live_ring_buffer = LiveRingBuffer(
            capacities={category: 3 for category in DEFAULT_CAPACITIES},
            max_query_limit=2,
        )

    def tearDown(self):
        sniffer_service._live_ring_buffer = self.original_ring
        app.dependency_overrides.clear()

    def test_recent_endpoint_returns_only_redacted_bounded_records(self):
        sniffer_service._live_ring_buffer.append(
            "packet",
            {"id": "packet-1", "authorization": "Bearer api-secret"},
            flow_key="flow-1",
        )

        response = self.client.get("/api/live/recent?type=packet&limit=999")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["limit"], 2)
        self.assertNotIn("api-secret", response.text)

    def test_recent_endpoint_rejects_unknown_category(self):
        response = self.client.get("/api/live/recent?type=unknown")
        self.assertEqual(response.status_code, 400)

    def test_ring_metrics_endpoint_and_monitoring_snapshot(self):
        self.assertEqual(self.client.get("/api/live/ring/metrics").status_code, 200)
        response = self.client.get("/api/monitoring/metrics")
        self.assertEqual(response.status_code, 200)
        self.assertIn("live_ring_buffer", response.json())


if __name__ == "__main__":
    unittest.main()
