from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any

from backend.app.bootstrap import ensure_project_root_on_path

ensure_project_root_on_path()

from log_manager import insert_batch, is_persist_enabled  # noqa: E402

logger = logging.getLogger(__name__)


class SnifferPersistence:
    def __init__(
        self,
        batch_size: int = 100,
        flush_interval: float = 0.5,
        max_queue_size: int = 5000,
        max_batch_size: int | None = None,
        overload_policy: str = "drop_oldest",
    ) -> None:
        self._batch_size = max(1, int(batch_size))
        self._max_batch_size = max(self._batch_size, int(max_batch_size or max(self._batch_size * 4, 400)))
        self._flush_interval = max(0.1, float(flush_interval))
        self._queue: queue.Queue[tuple[dict[str, Any], list[dict[str, Any]]]] = queue.Queue(maxsize=max_queue_size)
        self._overload_policy = overload_policy if overload_policy in {"drop_oldest", "drop_newest"} else "drop_oldest"
        self._stop_event = threading.Event()
        self._worker = threading.Thread(target=self._worker_loop, daemon=True, name="SnifferPersistenceWorker")
        self._lock = threading.Lock()
        self._dropped_writes = 0
        self._persisted_packets = 0
        self._persisted_alerts = 0
        self._flush_batches = 0
        self._last_flush_ms = 0.0
        self._avg_flush_ms = 0.0
        self._avg_batch_size = 0.0
        self._flush_errors = 0
        self._flush_retries = 0
        self._queue_high_water_mark = 0
        self._last_batch_size = 0
        self._last_queue_drift_ms = 0.0
        self._drain_completed = 0
        self._shutdown_flush_timeout = 0
        self._worker.start()

    def persist(self, packet: dict[str, Any], alerts: list[dict[str, Any]]) -> None:
        if not is_persist_enabled():
            return

        packet_row = {
            "ts": packet.get("ts"),
            "src": packet.get("src"),
            "dst": packet.get("dst"),
            "proto": packet.get("proto"),
            "sport": packet.get("sport"),
            "dport": packet.get("dport"),
            "length": packet.get("length"),
            "country": packet.get("country") or packet.get("country_code"),
            "org": packet.get("org"),
            "summary": packet.get("summary"),
            "is_alert": bool(alerts),
            "remote_ip": packet.get("remote_ip"),
        }
        alert_rows = [
            {
                "ts": alert.get("ts"),
                "src": alert.get("src"),
                "dst": alert.get("dst"),
                "proto": alert.get("proto"),
                "attack_type": alert.get("attack_type"),
                "score": alert.get("score"),
                "detail": alert.get("detail"),
                "severity": alert.get("severity"),
                "engine": alert.get("engine"),
                "score_raw": alert.get("score_raw"),
                "incident_id": alert.get("incident_id"),
                "incident_count": alert.get("incident_count"),
                "incident_score": alert.get("incident_score"),
                "packet_id": alert.get("packet_id"),
                "remote_ip": alert.get("remote_ip") or packet.get("remote_ip"),
            }
            for alert in alerts
        ]

        try:
            self._queue.put_nowait((packet_row, alert_rows))
            with self._lock:
                self._queue_high_water_mark = max(self._queue_high_water_mark, self._queue.qsize())
        except queue.Full:
            if self._overload_policy == "drop_newest":
                with self._lock:
                    self._dropped_writes += 1
                    self._queue_high_water_mark = max(self._queue_high_water_mark, self._queue.qsize())
                logger.warning("persistence queue full; dropping newest packet row")
                return
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            with self._lock:
                self._dropped_writes += 1
            try:
                self._queue.put_nowait((packet_row, alert_rows))
                with self._lock:
                    self._queue_high_water_mark = max(self._queue_high_water_mark, self._queue.qsize())
            except queue.Full:
                with self._lock:
                    self._dropped_writes += 1
                logger.warning("persistence queue full; dropping packet row")

    def stats(self) -> dict[str, int | float]:
        with self._lock:
            return {
                "dropped_writes": self._dropped_writes,
                "persisted_packets": self._persisted_packets,
                "persisted_alerts": self._persisted_alerts,
                "queue_size": self._queue.qsize(),
                "flush_batches": self._flush_batches,
                "last_flush_ms": self._last_flush_ms,
                "avg_flush_ms": self._avg_flush_ms,
                "last_batch_size": self._last_batch_size,
                "avg_batch_size": self._avg_batch_size,
                "flush_errors": self._flush_errors,
                "flush_retries": self._flush_retries,
                "queue_high_water_mark": self._queue_high_water_mark,
                "last_queue_drift_ms": self._last_queue_drift_ms,
                "overload_policy": self._overload_policy,
                "drain_completed": self._drain_completed,
                "shutdown_flush_timeout": self._shutdown_flush_timeout,
            }

    def close(self, timeout_sec: float = 10.0) -> None:
        self._stop_event.set()
        if self._worker.is_alive():
            self._worker.join(timeout=max(2.0, timeout_sec))
        with self._lock:
            if self._worker.is_alive():
                self._shutdown_flush_timeout = 1
            elif self._queue.empty():
                self._drain_completed = 1

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                first_packet, first_alerts = self._queue.get(timeout=self._flush_interval)
            except queue.Empty:
                continue

            packet_rows = [first_packet]
            alert_rows = list(first_alerts)
            deadline = time.time() + self._flush_interval
            target_batch_size = self._target_batch_size()

            while len(packet_rows) < target_batch_size:
                try:
                    remaining = max(0.0, deadline - time.time())
                    if remaining == 0.0:
                        break
                    next_packet, next_alerts = self._queue.get(timeout=remaining)
                except queue.Empty:
                    break
                packet_rows.append(next_packet)
                alert_rows.extend(next_alerts)

            try:
                started = time.perf_counter()
                result = insert_batch(packet_rows, alert_rows)
                duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
                drift_ms = round(max(0.0, time.time() - deadline) * 1000.0, 2)
                retries = int(result.get("retries", 0)) if isinstance(result, dict) else 0
                with self._lock:
                    self._persisted_packets += len(packet_rows)
                    self._persisted_alerts += len(alert_rows)
                    self._flush_batches += 1
                    self._last_flush_ms = duration_ms
                    self._avg_flush_ms = round(((self._avg_flush_ms * (self._flush_batches - 1)) + duration_ms) / self._flush_batches, 2)
                    self._last_batch_size = len(packet_rows)
                    self._avg_batch_size = round(((self._avg_batch_size * (self._flush_batches - 1)) + len(packet_rows)) / self._flush_batches, 2)
                    self._flush_retries += retries
                    self._last_queue_drift_ms = drift_ms
            except Exception:
                with self._lock:
                    self._flush_errors += 1
                logger.exception("Failed to persist packet batch")

    def _target_batch_size(self) -> int:
        queue_size = self._queue.qsize()
        if queue_size <= 0:
            return self._batch_size
        adaptive_bonus = max(0, queue_size // 50)
        return min(self._max_batch_size, max(self._batch_size, self._batch_size + adaptive_bonus))
