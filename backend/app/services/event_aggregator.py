from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from statistics import mean
from typing import Any, Callable

from backend.app.services.redaction import redact_sensitive_data


VALID_SLOW_CLIENT_POLICIES = {"coalesce", "drop_oldest", "drop_newest"}


def _positive_int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


def _policy_env() -> str:
    value = os.environ.get("NETBOT_WS_SLOW_CLIENT_POLICY", "coalesce")
    return value if value in VALID_SLOW_CLIENT_POLICIES else "coalesce"


class EventAggregator:
    """Batch high-frequency live events before websocket fan-out."""

    def __init__(
        self,
        emit: Callable[[dict[str, Any]], None],
        *,
        packet_batch_ms: int | None = None,
        packet_batch_max: int | None = None,
        alert_batch_ms: int | None = None,
        alert_batch_max: int | None = None,
        flow_batch_ms: int | None = None,
        flow_batch_max: int | None = None,
        summary_batch_ms: int | None = None,
        agent_batch_ms: int | None = None,
    ) -> None:
        self.packet_batch_ms = packet_batch_ms or _positive_int_env(
            "NETBOT_WS_PACKET_BATCH_MS", 500
        )
        self.packet_batch_max = packet_batch_max or _positive_int_env(
            "NETBOT_WS_PACKET_BATCH_MAX", 250
        )
        self.alert_batch_ms = alert_batch_ms or _positive_int_env(
            "NETBOT_WS_ALERT_BATCH_MS", 500
        )
        self.alert_batch_max = alert_batch_max or _positive_int_env(
            "NETBOT_WS_ALERT_BATCH_MAX", 100
        )
        self.flow_batch_ms = flow_batch_ms or _positive_int_env(
            "NETBOT_WS_FLOW_BATCH_MS", 1000
        )
        self.flow_batch_max = flow_batch_max or _positive_int_env(
            "NETBOT_WS_FLOW_BATCH_MAX", 200
        )
        self.summary_batch_ms = summary_batch_ms or _positive_int_env(
            "NETBOT_WS_SUMMARY_BATCH_MS", 1000
        )
        self.agent_batch_ms = agent_batch_ms or _positive_int_env(
            "NETBOT_WS_AGENT_BATCH_MS", 5000
        )
        self.client_queue_max = _positive_int_env("NETBOT_WS_CLIENT_QUEUE_MAX", 1000)
        self.slow_client_policy = _policy_env()
        self._emit = emit
        self._lock = threading.Lock()
        self._packet_events: list[dict[str, Any]] = []
        self._alert_events: list[dict[str, Any]] = []
        self._flow_events: list[dict[str, Any]] = []
        self._agent_events: list[dict[str, Any]] = []
        self._dashboard_summary: dict[str, Any] | None = None
        self._ops_health: dict[str, Any] | None = None
        self._timers: dict[str, threading.Timer] = {}
        self._batches_sent_total = 0
        self._events_received_total = 0
        self._events_sent_total = 0
        self._events_coalesced_total = 0
        self._events_dropped_total = 0
        self._batch_sizes: list[int] = []
        self._last_batch_at = ""
        self._last_drop_reason = ""

    def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        message = self._envelope(event_type, payload)
        if event_type == "packet:new":
            self._append_buffer("packet", message, self.packet_batch_max)
            return
        if event_type == "alert:new":
            self._append_buffer("alert", message, self.alert_batch_max)
            return
        if event_type.startswith("flow:"):
            self._append_buffer("flow", message, self.flow_batch_max)
            return
        if event_type.startswith("agent:"):
            self._append_buffer("agent", message, self.flow_batch_max)
            return
        if event_type in {"dashboard:summary", "sniffer:started", "sniffer:stopped"}:
            self._coalesce("dashboard", message)
            return
        if event_type == "ops:health":
            self._coalesce("ops", message)
            return
        self._record_received()
        self._emit(message)

    def flush_all(self) -> None:
        self._flush("packet")
        self._flush("alert")
        self._flush("flow")
        self._flush("agent")
        self._flush("dashboard")
        self._flush("ops")

    def close(self) -> None:
        """Flush pending events and cancel timers during shutdown."""

        with self._lock:
            timers = list(self._timers.values())
            self._timers = {}
        for timer in timers:
            timer.cancel()
        self.flush_all()

    def stats(self) -> dict[str, Any]:
        with self._lock:
            pending_packet = len(self._packet_events)
            pending_alert = len(self._alert_events)
            pending_flow = len(self._flow_events)
            batch_avg = round(mean(self._batch_sizes), 2) if self._batch_sizes else 0.0
            pressure_reasons: list[str] = []
            if self._events_dropped_total:
                pressure_reasons.append("websocket_events_dropped")
            if self._events_coalesced_total:
                pressure_reasons.append("websocket_events_coalesced")
            health = "degraded" if pressure_reasons else "healthy"
            if self._events_dropped_total >= self.client_queue_max:
                health = "critical"
            return {
                "enabled": True,
                "packet_batch_ms": self.packet_batch_ms,
                "packet_batch_max": self.packet_batch_max,
                "alert_batch_ms": self.alert_batch_ms,
                "alert_batch_max": self.alert_batch_max,
                "flow_batch_ms": self.flow_batch_ms,
                "flow_batch_max": self.flow_batch_max,
                "summary_batch_ms": self.summary_batch_ms,
                "agent_batch_ms": self.agent_batch_ms,
                "client_queue_max": self.client_queue_max,
                "slow_client_policy": self.slow_client_policy,
                "pending_packet_events": pending_packet,
                "pending_alert_events": pending_alert,
                "pending_flow_events": pending_flow,
                "batches_sent_total": self._batches_sent_total,
                "events_received_total": self._events_received_total,
                "events_sent_total": self._events_sent_total,
                "events_coalesced_total": self._events_coalesced_total,
                "events_dropped_total": self._events_dropped_total,
                "websocket_batch_size_avg": batch_avg,
                "last_batch_at": self._last_batch_at,
                "last_drop_reason": self._last_drop_reason,
                "health": health,
                "pressure_reasons": pressure_reasons,
            }

    def record_dropped(self, count: int = 1, reason: str = "client_queue_full") -> None:
        with self._lock:
            self._events_dropped_total += max(0, int(count))
            self._last_drop_reason = reason

    def record_coalesced(self, count: int = 1) -> None:
        with self._lock:
            self._events_coalesced_total += max(0, int(count))

    def _append_buffer(self, category: str, message: dict[str, Any], max_size: int) -> None:
        self._record_received()
        should_flush = False
        with self._lock:
            buffer = self._buffer_for(category)
            buffer.append(message)
            should_flush = len(buffer) >= max_size
        if should_flush:
            self._flush(category)
            return
        self._schedule(category)

    def _coalesce(self, category: str, message: dict[str, Any]) -> None:
        self._record_received()
        with self._lock:
            if category == "dashboard":
                if self._dashboard_summary is not None:
                    self._events_coalesced_total += 1
                self._dashboard_summary = message
            else:
                if self._ops_health is not None:
                    self._events_coalesced_total += 1
                self._ops_health = message
        self._schedule(category)

    def _flush(self, category: str) -> None:
        with self._lock:
            timer = self._timers.pop(category, None)
            if timer:
                timer.cancel()
            if category == "packet":
                events = self._packet_events
                self._packet_events = []
                batch = self._batch("packet_batch", "events", events)
            elif category == "alert":
                events = self._alert_events
                self._alert_events = []
                batch = self._batch("alert_batch", "events", events)
            elif category == "flow":
                events = self._flow_events
                self._flow_events = []
                batch = self._batch("flow_delta", "updates", events)
            elif category == "agent":
                events = self._agent_events
                self._agent_events = []
                batch = self._batch("agent_status_batch", "agents", events)
            elif category == "dashboard":
                message = self._dashboard_summary
                self._dashboard_summary = None
                batch = self._summary("dashboard_summary", "summary", message)
            elif category == "ops":
                message = self._ops_health
                self._ops_health = None
                batch = self._summary("ops_health_update", "health", message)
            else:
                return
            if not batch:
                return
            self._batches_sent_total += 1
            self._events_sent_total += int(batch.get("count") or 1)
            self._batch_sizes.append(int(batch.get("count") or 1))
            self._batch_sizes = self._batch_sizes[-100:]
            self._last_batch_at = batch["timestamp"]
        self._emit(batch)

    def _schedule(self, category: str) -> None:
        with self._lock:
            if category in self._timers:
                return
            delay = self._delay_for(category) / 1000.0
            timer = threading.Timer(delay, lambda: self._flush(category))
            timer.daemon = True
            self._timers[category] = timer
            timer.start()

    def _delay_for(self, category: str) -> int:
        if category == "packet":
            return self.packet_batch_ms
        if category == "alert":
            return self.alert_batch_ms
        if category == "flow":
            return self.flow_batch_ms
        if category == "agent":
            return self.agent_batch_ms
        return self.summary_batch_ms

    def _buffer_for(self, category: str) -> list[dict[str, Any]]:
        if category == "packet":
            return self._packet_events
        if category == "alert":
            return self._alert_events
        if category == "flow":
            return self._flow_events
        return self._agent_events

    def _record_received(self) -> None:
        with self._lock:
            self._events_received_total += 1

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _envelope(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "version": 1,
            "type": event_type,
            "timestamp": self._now(),
            "payload": redact_sensitive_data(payload),
        }

    def _batch(
        self, message_type: str, field: str, events: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        if not events:
            return None
        return {
            "version": 1,
            "type": message_type,
            "timestamp": self._now(),
            "count": len(events),
            field: events,
        }

    def _summary(
        self, message_type: str, field: str, message: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        if not message:
            return None
        return {
            "version": 1,
            "type": message_type,
            "timestamp": self._now(),
            "count": 1,
            field: message.get("payload", {}),
        }


__all__ = ["EventAggregator", "VALID_SLOW_CLIENT_POLICIES"]
