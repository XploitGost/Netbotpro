from __future__ import annotations

import asyncio
import threading
import time
from datetime import datetime, timezone
from statistics import median
from typing import Any

from backend.app.services.event_aggregator import EventAggregator


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[asyncio.Queue[dict[str, Any]], asyncio.AbstractEventLoop | None] = {}
        self._lock = threading.Lock()
        self._dropped_subscribers = 0
        self._dropped_messages = 0
        self._published_messages = 0
        self._slow_clients = 0
        self._coalesced_for_slow_client = 0
        self._dropped_for_slow_client = 0
        self._send_errors_total = 0
        self._send_latencies: list[float] = []
        self._last_drop_reason = ""
        self._aggregator = EventAggregator(self._publish_direct)

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(
            maxsize=self._aggregator.client_queue_max
        )
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        with self._lock:
            self._subscribers[queue] = loop
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        with self._lock:
            self._subscribers.pop(queue, None)

    def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        self._aggregator.publish(event_type, payload)

    def flush(self) -> None:
        self._aggregator.flush_all()

    def _publish_direct(self, message: dict[str, Any]) -> None:
        message = {
            **message,
            "timestamp": message.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            subscribers = list(self._subscribers.items())
            self._published_messages += 1
        for queue, loop in subscribers:
            if loop is not None and loop.is_running():
                try:
                    loop.call_soon_threadsafe(self._safe_put, queue, message)
                except RuntimeError:
                    with self._lock:
                        self._subscribers.pop(queue, None)
                        self._dropped_subscribers += 1
            else:
                self._safe_put(queue, message)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "subscribers": len(self._subscribers),
                "dropped_subscribers": self._dropped_subscribers,
                "dropped_messages": self._dropped_messages,
                "published_messages": self._published_messages,
            }

    def event_aggregator_stats(self) -> dict[str, Any]:
        return self._aggregator.stats()

    def websocket_stats(self) -> dict[str, Any]:
        with self._lock:
            depths = [queue.qsize() for queue in self._subscribers]
            p50 = _percentile(self._send_latencies, 50)
            p95 = _percentile(self._send_latencies, 95)
            pressure_reasons: list[str] = []
            if self._slow_clients:
                pressure_reasons.append("websocket_slow_clients")
            if self._dropped_for_slow_client:
                pressure_reasons.append("websocket_events_dropped")
            if self._coalesced_for_slow_client:
                pressure_reasons.append("websocket_events_coalesced")
            if p95 >= 250.0:
                pressure_reasons.append("websocket_send_latency")
            if self._send_errors_total:
                pressure_reasons.append("websocket_send_errors")
            health = "healthy"
            if pressure_reasons:
                health = "degraded"
            if self._send_errors_total >= 3 or self._dropped_for_slow_client >= self._aggregator.client_queue_max:
                health = "critical"
            return {
                "clients": len(self._subscribers),
                "websocket_clients": len(self._subscribers),
                "slow_clients": self._slow_clients,
                "websocket_slow_clients": self._slow_clients,
                "client_queue_max": self._aggregator.client_queue_max,
                "client_queue_depth_max": max(depths, default=0),
                "websocket_client_queue_depth": max(depths, default=0),
                "send_latency_ms_p50": p50,
                "send_latency_ms_p95": p95,
                "websocket_send_latency_ms": p95,
                "send_errors_total": self._send_errors_total,
                "dropped_for_slow_client_total": self._dropped_for_slow_client,
                "coalesced_for_slow_client_total": self._coalesced_for_slow_client,
                "last_drop_reason": self._last_drop_reason,
                "websocket_last_drop_reason": self._last_drop_reason,
                "health": health,
                "pressure_reasons": pressure_reasons,
            }

    def record_send_latency(self, started_at: float, *, ok: bool = True) -> None:
        elapsed_ms = max(0.0, (time.perf_counter() - started_at) * 1000.0)
        with self._lock:
            self._send_latencies.append(elapsed_ms)
            self._send_latencies = self._send_latencies[-200:]
            if not ok:
                self._send_errors_total += 1

    def _safe_put(self, queue: asyncio.Queue[dict[str, Any]], message: dict[str, Any]) -> None:
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            self._handle_full_queue(queue, message)

    def _handle_full_queue(
        self, queue: asyncio.Queue[dict[str, Any]], message: dict[str, Any]
    ) -> None:
        policy = self._aggregator.slow_client_policy
        with self._lock:
            self._slow_clients += 1
            self._dropped_messages += 1
        if policy == "drop_newest":
            with self._lock:
                self._dropped_for_slow_client += 1
                self._last_drop_reason = "client_queue_full_drop_newest"
            self._aggregator.record_dropped(reason="client_queue_full_drop_newest")
            return

        try:
            queue.get_nowait()
            queue.task_done()
        except asyncio.QueueEmpty:
            pass

        if policy == "coalesce":
            with self._lock:
                self._coalesced_for_slow_client += 1
                self._last_drop_reason = "client_queue_full_coalesce"
            self._aggregator.record_coalesced()
        else:
            with self._lock:
                self._dropped_for_slow_client += 1
                self._last_drop_reason = "client_queue_full_drop_oldest"
            self._aggregator.record_dropped(reason="client_queue_full_drop_oldest")

        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            with self._lock:
                self._dropped_for_slow_client += 1
                self._last_drop_reason = "client_queue_full_after_policy"
            self._aggregator.record_dropped(reason="client_queue_full_after_policy")


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if percentile == 50:
        return round(float(median(ordered)), 2)
    index = min(len(ordered) - 1, max(0, int(round((percentile / 100) * len(ordered))) - 1))
    return round(float(ordered[index]), 2)
