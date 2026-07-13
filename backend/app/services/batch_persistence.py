from __future__ import annotations

import logging
import os
import queue
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from backend.app.services.redaction import redact_sensitive_data

logger = logging.getLogger(__name__)

EVENT_TYPES = {
    "packet_record",
    "flow_record",
    "alert_record",
    "protocol_metadata",
    "report_record",
    "agent_telemetry",
    "agent_heartbeat",
    "ops_snapshot",
    "generic_history_event",
}


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return (
        default
        if value is None
        else value.strip().lower() in {"1", "true", "yes", "on"}
    )


@dataclass(frozen=True)
class PersistenceEvent:
    type: str
    timestamp: str
    payload: dict[str, Any]
    source: str
    priority: str
    queued_at: float

    def public(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "source": self.source,
            "priority": self.priority,
        }


@dataclass
class _FlushCommand:
    completed: threading.Event


@dataclass(frozen=True)
class _EventGroup:
    events: tuple[PersistenceEvent, ...]


class BatchPersistenceWriter:
    """Bounded, redacting write-behind queue for non-audit history records."""

    def __init__(
        self,
        write_batch: Callable[[dict[str, list[dict[str, Any]]]], Any],
        *,
        enabled: bool | None = None,
        queue_max: int | None = None,
        overflow_policy: str | None = None,
        retry_max: int | None = None,
        retry_backoff_ms: int | None = None,
        batch_sizes: dict[str, int] | None = None,
        flush_ms: dict[str, int] | None = None,
    ) -> None:
        self._write_batch = write_batch
        self._enabled = (
            _env_bool("NETBOT_PERSISTENCE_BATCH_ENABLED", True)
            if enabled is None
            else enabled
        )
        self._queue_max = max(
            1, int(queue_max or os.environ.get("NETBOT_PERSISTENCE_QUEUE_MAX", "5000"))
        )
        policy = overflow_policy or os.environ.get(
            "NETBOT_PERSISTENCE_OVERFLOW_POLICY", "drop_oldest"
        )
        self._overflow_policy = (
            policy
            if policy in {"drop_oldest", "drop_newest", "reject_new"}
            else "drop_oldest"
        )
        self._retry_max = max(
            0,
            int(
                retry_max
                if retry_max is not None
                else os.environ.get("NETBOT_PERSISTENCE_RETRY_MAX", "3")
            ),
        )
        self._retry_backoff_ms = max(
            0,
            int(
                retry_backoff_ms
                if retry_backoff_ms is not None
                else os.environ.get("NETBOT_PERSISTENCE_RETRY_BACKOFF_MS", "250")
            ),
        )
        self._batch_sizes = {
            "packet_record": int(
                os.environ.get("NETBOT_PERSISTENCE_PACKET_BATCH_SIZE", "500")
            ),
            "flow_record": int(
                os.environ.get("NETBOT_PERSISTENCE_FLOW_BATCH_SIZE", "250")
            ),
            "alert_record": int(
                os.environ.get("NETBOT_PERSISTENCE_ALERT_BATCH_SIZE", "100")
            ),
            "agent_telemetry": int(
                os.environ.get("NETBOT_PERSISTENCE_AGENT_BATCH_SIZE", "100")
            ),
            "agent_heartbeat": int(
                os.environ.get("NETBOT_PERSISTENCE_AGENT_BATCH_SIZE", "100")
            ),
        }
        self._flush_ms = {
            "packet_record": int(
                os.environ.get("NETBOT_PERSISTENCE_PACKET_FLUSH_MS", "1000")
            ),
            "flow_record": int(
                os.environ.get("NETBOT_PERSISTENCE_FLOW_FLUSH_MS", "1500")
            ),
            "alert_record": int(
                os.environ.get("NETBOT_PERSISTENCE_ALERT_FLUSH_MS", "1000")
            ),
            "agent_telemetry": int(
                os.environ.get("NETBOT_PERSISTENCE_AGENT_FLUSH_MS", "3000")
            ),
            "agent_heartbeat": int(
                os.environ.get("NETBOT_PERSISTENCE_AGENT_FLUSH_MS", "3000")
            ),
        }
        self._batch_sizes.update(batch_sizes or {})
        self._flush_ms.update(flush_ms or {})
        self._queue: queue.Queue[PersistenceEvent | _EventGroup | _FlushCommand] = (
            queue.Queue(maxsize=self._queue_max)
        )
        self._buffers: dict[str, list[PersistenceEvent]] = defaultdict(list)
        self._first_buffered_at: dict[str, float] = {}
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._events_received = self._events_written = self._events_dropped = 0
        self._events_failed = self._batches_written = self._retry_total = 0
        self._high_water = 0
        self._last_flush_at = self._last_error = self._last_drop_reason = ""
        self._latencies: deque[float] = deque(maxlen=512)
        self._worker = threading.Thread(
            target=self._run, name="netbotpro-batch-persistence", daemon=True
        )
        if self._enabled:
            self._worker.start()

    def enqueue(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        source: str = "backend",
        priority: str = "normal",
        timestamp: str | None = None,
    ) -> bool:
        normalized_type = (
            event_type if event_type in EVENT_TYPES else "generic_history_event"
        )
        event = PersistenceEvent(
            type=normalized_type,
            timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
            payload=redact_sensitive_data(dict(payload)),
            source=str(source),
            priority=(
                priority
                if priority in {"low", "normal", "high", "critical"}
                else "normal"
            ),
            queued_at=time.monotonic(),
        )
        if not self._enabled:
            return self._write_synchronously((event,))
        with self._lock:
            self._events_received += 1
        try:
            self._queue.put_nowait(event)
            self._record_high_water()
            return True
        except queue.Full:
            return self._handle_overflow(event)

    def enqueue_many(self, events: list[dict[str, Any]]) -> bool:
        """Enqueue related records as one bounded persistence work unit."""
        if not events:
            return False
        normalized = tuple(
            PersistenceEvent(
                type=(
                    item["type"]
                    if item.get("type") in EVENT_TYPES
                    else "generic_history_event"
                ),
                timestamp=str(
                    item.get("timestamp") or datetime.now(timezone.utc).isoformat()
                ),
                payload=redact_sensitive_data(dict(item.get("payload") or {})),
                source=str(item.get("source") or "backend"),
                priority=(
                    item.get("priority")
                    if item.get("priority") in {"low", "normal", "high", "critical"}
                    else "normal"
                ),
                queued_at=time.monotonic(),
            )
            for item in events
        )
        group = _EventGroup(normalized)
        if not self._enabled:
            return self._write_synchronously(normalized)
        with self._lock:
            self._events_received += len(normalized)
        try:
            self._queue.put_nowait(group)
            self._record_high_water()
            return True
        except queue.Full:
            return self._handle_overflow(group)

    def flush(self, timeout_sec: float = 10.0) -> bool:
        if not self._enabled or not self._worker.is_alive():
            return not self._enabled
        command = _FlushCommand(threading.Event())
        try:
            self._queue.put(command, timeout=max(0.1, timeout_sec / 2))
        except queue.Full:
            return False
        return command.completed.wait(max(0.1, timeout_sec))

    def close(self, timeout_sec: float = 10.0) -> None:
        if not self._enabled:
            return
        self.flush(timeout_sec=max(0.1, timeout_sec / 2))
        self._stop.set()
        self._worker.join(timeout=max(0.1, timeout_sec))

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            depth = min(
                self._queue_max,
                self._queued_event_depth()
                + sum(len(rows) for rows in self._buffers.values()),
            )
            utilization = round(min(100.0, depth / self._queue_max * 100.0), 2)
            latencies = sorted(self._latencies)
            p95 = (
                latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))]
                if latencies
                else 0.0
            )
            oldest = min(
                (event.queued_at for rows in self._buffers.values() for event in rows),
                default=None,
            )
            backlog_age = (
                round(max(0.0, time.monotonic() - oldest) * 1000.0, 2)
                if oldest
                else 0.0
            )
            worker_alive = self._worker.is_alive() if self._enabled else False
            reasons: list[str] = []
            if utilization >= 80:
                reasons.append("persistence_queue_backlog")
            if self._high_water >= max(1, int(self._queue_max * 0.9)):
                reasons.append("persistence_queue_high_water")
            if self._events_dropped:
                reasons.append("persistence_dropped_events")
            if self._events_failed:
                reasons.append("persistence_failed_events")
            if self._enabled and not worker_alive and not self._stop.is_set():
                reasons.append("persistence_worker_stopped")
            health = "degraded" if reasons else "healthy"
            if self._events_failed >= 3 or (
                self._enabled and not worker_alive and not self._stop.is_set()
            ):
                health = "critical"
            return {
                "persistence_enabled": self._enabled,
                "queue_depth": depth,
                "queue_max": self._queue_max,
                "queue_utilization_percent": utilization,
                "batches_written_total": self._batches_written,
                "events_received_total": self._events_received,
                "events_written_total": self._events_written,
                "events_dropped_total": self._events_dropped,
                "events_failed_total": self._events_failed,
                "retry_total": self._retry_total,
                "high_water_mark": self._high_water,
                "overflow_policy": self._overflow_policy,
                "worker_alive": worker_alive,
                "last_flush_at": self._last_flush_at,
                "last_error": self._last_error,
                "last_drop_reason": self._last_drop_reason,
                "write_latency_avg_ms": (
                    round(sum(latencies) / len(latencies), 2) if latencies else 0.0
                ),
                "write_latency_p95_ms": round(p95, 2),
                "backlog_age_ms": backlog_age,
                "health": health,
                "pressure_reasons": reasons,
            }

    def _handle_overflow(self, event: PersistenceEvent | _EventGroup) -> bool:
        reason = f"queue_full_{self._overflow_policy}"
        if self._overflow_policy == "drop_oldest":
            try:
                dropped = self._queue.get_nowait()
                self._queue.task_done()
                if isinstance(dropped, _FlushCommand):
                    dropped.completed.set()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(event)
                accepted = True
            except queue.Full:
                accepted = False
        else:
            accepted = False
        with self._lock:
            self._events_dropped += (
                len(event.events) if isinstance(event, _EventGroup) else 1
            )
            self._last_drop_reason = reason
        logger.warning("persistence event dropped reason=%s", reason)
        self._record_high_water()
        return accepted

    def _record_high_water(self) -> None:
        with self._lock:
            self._high_water = min(
                self._queue_max,
                max(self._high_water, self._queued_event_depth()),
            )

    def _queued_event_depth(self) -> int:
        with self._queue.mutex:
            return sum(
                (
                    len(item.events)
                    if isinstance(item, _EventGroup)
                    else (0 if isinstance(item, _FlushCommand) else 1)
                )
                for item in self._queue.queue
            )

    def _run(self) -> None:
        while not self._stop.is_set() or not self._queue.empty() or self._buffers:
            timeout = self._next_timeout()
            try:
                item = self._queue.get(timeout=timeout)
            except queue.Empty:
                self._flush_due()
                continue
            try:
                if isinstance(item, _FlushCommand):
                    self._flush_due(force=True)
                    item.completed.set()
                    continue
                events = item.events if isinstance(item, _EventGroup) else (item,)
                urgent = False
                size_due = False
                for event in events:
                    self._buffers[event.type].append(event)
                    self._first_buffered_at.setdefault(event.type, time.monotonic())
                    urgent = urgent or event.priority in {"high", "critical"}
                    size_due = size_due or len(
                        self._buffers[event.type]
                    ) >= self._batch_size(event.type)
                if urgent or size_due:
                    self._flush_due(force=True)
                else:
                    self._flush_due()
            finally:
                self._queue.task_done()
        self._flush_due(force=True)

    def _next_timeout(self) -> float:
        if not self._buffers:
            return 0.1
        now = time.monotonic()
        due = [
            started + self._flush_interval(kind) - now
            for kind, started in self._first_buffered_at.items()
        ]
        return max(0.001, min([0.1, *due]))

    def _batch_size(self, event_type: str) -> int:
        return max(1, int(self._batch_sizes.get(event_type, 100)))

    def _flush_interval(self, event_type: str) -> float:
        return max(0.001, int(self._flush_ms.get(event_type, 2000)) / 1000.0)

    def _flush_due(self, *, force: bool = False, types: set[str] | None = None) -> None:
        now = time.monotonic()
        due_types = types or {
            kind
            for kind, started in self._first_buffered_at.items()
            if force or now - started >= self._flush_interval(kind)
        }
        grouped = {
            kind: [event.public() for event in self._buffers[kind]]
            for kind in due_types
            if self._buffers.get(kind)
        }
        if not grouped:
            return
        # Once handed to the storage call these records are in-flight, not queued
        # backlog. Removing them here keeps queue depth bounded and truthful.
        for kind in grouped:
            self._buffers.pop(kind, None)
            self._first_buffered_at.pop(kind, None)
        events = sum(len(rows) for rows in grouped.values())
        started = time.perf_counter()
        try:
            retries = self._write_with_retry(grouped)
            latency = (time.perf_counter() - started) * 1000.0
            with self._lock:
                self._events_written += events
                self._batches_written += 1
                self._retry_total += retries
                self._latencies.append(latency)
                self._last_flush_at = datetime.now(timezone.utc).isoformat()
                self._last_error = ""
        except Exception as exc:
            with self._lock:
                self._events_failed += events
                self._last_error = type(exc).__name__
            logger.error(
                "persistence batch failed error_type=%s events=%s",
                type(exc).__name__,
                events,
            )

    def _write_with_retry(self, grouped: dict[str, list[dict[str, Any]]]) -> int:
        retries = 0
        while True:
            try:
                result = self._write_batch(grouped)
                storage_retries = (
                    int(result.get("retries", 0)) if isinstance(result, dict) else 0
                )
                return retries + storage_retries
            except Exception:
                if retries >= self._retry_max or self._stop.is_set():
                    raise
                delay = self._retry_backoff_ms / 1000.0 * (2**retries)
                retries += 1
                logger.warning(
                    "persistence retry attempt=%s delay_ms=%.0f",
                    retries,
                    delay * 1000.0,
                )
                if self._stop.wait(delay):
                    raise

    def _write_synchronously(self, events: tuple[PersistenceEvent, ...]) -> bool:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            grouped[event.type].append(event.public())
        with self._lock:
            self._events_received += len(events)
        started = time.perf_counter()
        try:
            retries = self._write_with_retry(dict(grouped))
            latency = (time.perf_counter() - started) * 1000.0
            with self._lock:
                self._events_written += len(events)
                self._batches_written += 1
                self._retry_total += retries
                self._latencies.append(latency)
                self._last_flush_at = datetime.now(timezone.utc).isoformat()
            return True
        except Exception as exc:
            with self._lock:
                self._events_failed += len(events)
                self._last_error = type(exc).__name__
            return False


__all__ = ["BatchPersistenceWriter", "EVENT_TYPES", "PersistenceEvent"]
