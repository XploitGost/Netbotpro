from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
import uuid
from collections import deque, OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

DEFAULT_WORKER_COUNT = 4
DEFAULT_QUEUE_MAX = 8192
DEFAULT_SHUTDOWN_TIMEOUT_SEC = 5.0
DEFAULT_ERROR_THRESHOLD = 25
DEFAULT_SLOW_JOB_MS = 100.0
HEALTH_WINDOW_SEC = 60.0
VALID_OVERFLOW_POLICIES = {
    "drop_oldest",
    "drop_newest",
    "reject_new",
    "block_short",
}


def _env_bool(name: str, default: bool) -> bool:
    value = str(os.environ.get(name, str(default))).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return min(maximum, max(minimum, value))


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return min(maximum, max(minimum, value))


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * percentile)))
    return round(ordered[index], 2)


@dataclass(frozen=True)
class FlowDispatchKey:
    value: str
    complete: bool

    @classmethod
    def from_packet(cls, packet: dict[str, Any]) -> FlowDispatchKey:
        src = str(packet.get("src") or packet.get("src_ip") or "").strip()
        dst = str(packet.get("dst") or packet.get("dst_ip") or "").strip()
        protocol = (
            str(
                packet.get("proto")
                or packet.get("transport")
                or packet.get("protocol")
                or ""
            )
            .strip()
            .upper()
        )
        src_port = _safe_port(packet.get("sport", packet.get("src_port")))
        dst_port = _safe_port(packet.get("dport", packet.get("dst_port")))

        if src and dst and protocol:
            if protocol in {"TCP", "UDP"}:
                endpoints = sorted(((src, src_port), (dst, dst_port)))
                left, right = endpoints
                return cls(
                    f"{protocol}|{left[0]}:{left[1]}|{right[0]}:{right[1]}",
                    True,
                )
            endpoints = sorted((src, dst))
            return cls(f"{protocol}|{endpoints[0]}|{endpoints[1]}", True)

        parts = [
            protocol or "OTHER",
            src or "-",
            str(src_port),
            dst or "-",
            str(dst_port),
        ]
        if any(value not in {"", "-", "0", "OTHER"} for value in parts):
            return cls("partial|" + "|".join(parts), False)
        return cls("unknown-flow", False)


def _safe_port(value: Any) -> int:
    try:
        port = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return port if 0 <= port <= 65535 else 0


@dataclass(frozen=True)
class FlowWorkerJob:
    job_id: str
    created_at: str
    flow_key: str
    packet: dict[str, Any]
    metadata: dict[str, str]
    priority: str = "normal"


@dataclass
class _WorkerState:
    worker_id: int
    thread: threading.Thread | None = None
    processed_total: int = 0
    failed_total: int = 0
    dropped_total: int = 0
    latencies_ms: deque[float] = field(default_factory=lambda: deque(maxlen=2048))


class FlowWorkerPool:
    """Bounded shared work with FIFO ordering and one active job per flow."""

    def __init__(
        self,
        processor: Callable[[dict[str, Any]], None],
        *,
        enabled: bool = True,
        worker_count: int = DEFAULT_WORKER_COUNT,
        queue_max: int = DEFAULT_QUEUE_MAX,
        overflow_policy: str = "drop_oldest",
        shutdown_timeout_sec: float = DEFAULT_SHUTDOWN_TIMEOUT_SEC,
        error_threshold: int = DEFAULT_ERROR_THRESHOLD,
        slow_job_ms: float = DEFAULT_SLOW_JOB_MS,
        block_timeout_sec: float = 0.05,
    ) -> None:
        self._processor = processor
        self.enabled = bool(enabled)
        self.worker_count = max(1, min(64, int(worker_count)))
        self.queue_max_total = max(self.worker_count, int(queue_max))
        self.overflow_policy = (
            overflow_policy
            if overflow_policy in VALID_OVERFLOW_POLICIES
            else "drop_oldest"
        )
        self.shutdown_timeout_sec = max(0.1, float(shutdown_timeout_sec))
        self.error_threshold = max(1, int(error_threshold))
        self.slow_job_ms = max(1.0, float(slow_job_ms))
        self.block_timeout_sec = max(0.001, min(1.0, float(block_timeout_sec)))
        self._lock = threading.RLock()
        self._queue_changed = threading.Condition(self._lock)
        self._queued_jobs = 0
        self._pending: OrderedDict[str, FlowWorkerJob] = OrderedDict()
        self._flow_queues: dict[str, deque[FlowWorkerJob]] = {}
        self._ready_flows: OrderedDict[str, None] = OrderedDict()
        self._active_flows: set[str] = set()
        self._active_by_worker: dict[int, str] = {}
        self._stop = threading.Event()
        self._accepting = True
        self._jobs_received = 0
        self._queue_high_water = 0
        self._jobs_processed = 0
        self._jobs_failed = 0
        self._jobs_dropped = 0
        self._jobs_rejected = 0
        self._recent_drops: deque[tuple[int, int]] = deque()
        self._recent_rejections: deque[tuple[int, int]] = deque()
        self._recent_failures: deque[tuple[int, int]] = deque()
        self._unknown_flow_keys = 0
        self._slow_jobs = 0
        self._latencies_ms: deque[float] = deque(maxlen=4096)
        self._last_error = ""
        self._last_drop_reason = ""
        self._last_pressure_log_at = float("-inf")
        self._last_slow_job_at = ""
        self._workers = self._create_workers()
        if self.enabled:
            self._start_workers()

    @classmethod
    def from_env(cls, processor: Callable[[dict[str, Any]], None]) -> FlowWorkerPool:
        policy = str(
            os.environ.get("NETBOT_FLOW_WORKER_OVERFLOW_POLICY", "drop_oldest")
        ).strip()
        if policy not in VALID_OVERFLOW_POLICIES:
            policy = "drop_oldest"
        return cls(
            processor,
            enabled=_env_bool("NETBOT_FLOW_WORKERS_ENABLED", True),
            worker_count=_env_int(
                "NETBOT_FLOW_WORKER_COUNT", DEFAULT_WORKER_COUNT, 1, 64
            ),
            queue_max=_env_int(
                "NETBOT_FLOW_WORKER_QUEUE_MAX", DEFAULT_QUEUE_MAX, 1, 1_000_000
            ),
            overflow_policy=policy,
            shutdown_timeout_sec=_env_float(
                "NETBOT_FLOW_WORKER_SHUTDOWN_TIMEOUT_SEC",
                DEFAULT_SHUTDOWN_TIMEOUT_SEC,
                0.1,
                120.0,
            ),
            error_threshold=_env_int(
                "NETBOT_FLOW_WORKER_ERROR_THRESHOLD",
                DEFAULT_ERROR_THRESHOLD,
                1,
                1_000_000,
            ),
            slow_job_ms=_env_float(
                "NETBOT_FLOW_WORKER_SLOW_JOB_MS", DEFAULT_SLOW_JOB_MS, 1.0, 60_000.0
            ),
        )

    def _create_workers(self) -> list[_WorkerState]:
        return [
            _WorkerState(
                worker_id=worker_id,
            )
            for worker_id in range(self.worker_count)
        ]

    def _start_workers(self) -> None:
        for state in self._workers:
            state.thread = threading.Thread(
                target=self._worker_loop,
                args=(state,),
                name=f"netbotpro-flow-worker-{state.worker_id}",
                daemon=True,
            )
            state.thread.start()

    def worker_index_for(self, packet: dict[str, Any]) -> int:
        key = FlowDispatchKey.from_packet(packet)
        return self._worker_index_for_key(key)

    def _worker_index_for_key(self, key: FlowDispatchKey) -> int:
        digest = hashlib.sha256(key.value.encode("utf-8")).digest()
        return int.from_bytes(digest[:8], "big") % self.worker_count

    def submit(
        self,
        packet: dict[str, Any],
        *,
        metadata: dict[str, str] | None = None,
        priority: str = "normal",
    ) -> bool:
        with self._lock:
            self._jobs_received += 1
            accepting = self._accepting
        if not accepting:
            self._record_rejection("worker_pool_closed")
            return False

        key = FlowDispatchKey.from_packet(packet)
        if not key.complete:
            with self._lock:
                self._unknown_flow_keys += 1

        if not self.enabled:
            self._process_inline(packet)
            return True

        job = FlowWorkerJob(
            job_id=uuid.uuid4().hex,
            created_at=datetime.now(timezone.utc).isoformat(),
            flow_key=key.value,
            packet=dict(packet),
            metadata=dict(
                metadata or {"source": "live_capture", "capture_mode": "live"}
            ),
            priority=str(priority or "normal"),
        )
        return self._enqueue(self._workers[self._worker_index_for_key(key)], job)

    def _put_job(self, job: FlowWorkerJob) -> None:
        self._pending[job.job_id] = job
        self._flow_queues.setdefault(job.flow_key, deque()).append(job)
        if job.flow_key not in self._active_flows:
            self._ready_flows[job.flow_key] = None
        self._queued_jobs += 1
        self._queue_high_water = max(self._queue_high_water, self._queued_jobs)
        self._queue_changed.notify_all()

    def _enqueue(self, state: _WorkerState, job: FlowWorkerJob) -> bool:
        # Queued flows are unassigned. Only an executing flow owns a worker.
        with self._queue_changed:
            if self.overflow_policy == "block_short":
                self._queue_changed.wait_for(
                    lambda: self._queued_jobs < self.queue_max_total or not self._accepting,
                    timeout=self.block_timeout_sec,
                )
            if not self._accepting:
                self._record_rejection("worker_pool_closed")
                return False
            if self._queued_jobs < self.queue_max_total:
                self._put_job(job)
                return True

            if self.overflow_policy == "drop_oldest":
                _, discarded = self._pending.popitem(last=False)
                items = self._flow_queues[discarded.flow_key]
                items.popleft()
                if not items:
                    del self._flow_queues[discarded.flow_key]
                    self._ready_flows.pop(discarded.flow_key, None)
                self._queued_jobs -= 1
                self._record_drop(state, "flow_worker_queue_full_drop_oldest")
                self._put_job(job)
                return True

            if self.overflow_policy == "drop_newest":
                self._record_drop(state, "flow_worker_queue_full_drop_newest")
                return False
            reason = (
                "flow_worker_queue_block_timeout"
                if self.overflow_policy == "block_short"
                else "flow_worker_queue_full_reject_new"
            )
            self._record_rejection(reason)
            return False

    def _record_drop(self, state: _WorkerState, reason: str) -> None:
        with self._lock:
            # Waiting jobs are unassigned; loss belongs to the shared queue.
            self._jobs_dropped += 1
            self._record_recent_event(self._recent_drops)
            self._last_drop_reason = reason
        self._log_pressure(reason)

    def _record_rejection(self, reason: str) -> None:
        with self._lock:
            self._jobs_rejected += 1
            self._record_recent_event(self._recent_rejections)
            self._last_drop_reason = reason
        self._log_pressure(reason)

    def _log_pressure(self, reason: str) -> None:
        with self._lock:
            now = time.monotonic()
            if now - self._last_pressure_log_at < 5.0:
                return
            self._last_pressure_log_at = now
            dropped, rejected = self._jobs_dropped, self._jobs_rejected
        logger.warning(
            "flow worker queue pressure reason=%s dropped_total=%s rejected_total=%s",
            reason, dropped, rejected,
        )

    def _worker_loop(self, state: _WorkerState) -> None:
        while True:
            with self._queue_changed:
                self._queue_changed.wait_for(lambda: self._ready_flows or (self._stop.is_set() and not self._queued_jobs), timeout=.1)
                if not self._ready_flows:
                    if self._stop.is_set() and not self._queued_jobs:
                        return
                    continue
                key, _ = self._ready_flows.popitem(last=False)
                items = self._flow_queues[key]
                job = items.popleft()
                if not items:
                    del self._flow_queues[key]
                del self._pending[job.job_id]
                self._queued_jobs -= 1
                self._active_flows.add(key)
                self._active_by_worker[state.worker_id] = key
                self._queue_changed.notify_all()
            started = time.perf_counter()
            failed = False
            try:
                self._processor(job.packet)
            except Exception as exc:  # pragma: no cover - behavior asserted via metrics
                failed = True
                with self._lock:
                    state.failed_total += 1
                    self._jobs_failed += 1
                    self._record_recent_event(self._recent_failures)
                    self._last_error = type(exc).__name__
                logger.error(
                    "flow worker job failed worker_id=%s error_type=%s",
                    state.worker_id,
                    type(exc).__name__,
                )
            finally:
                latency_ms = (time.perf_counter() - started) * 1000.0
                self._record_completion(state, latency_ms, failed)
                with self._queue_changed:
                    self._active_flows.remove(job.flow_key)
                    self._active_by_worker.pop(state.worker_id, None)
                    if self._flow_queues.get(job.flow_key):
                        self._ready_flows[job.flow_key] = None
                    self._queue_changed.notify_all()

    def _process_inline(self, packet: dict[str, Any]) -> None:
        started = time.perf_counter()
        try:
            self._processor(dict(packet))
        except Exception as exc:
            with self._lock:
                self._jobs_failed += 1
                self._record_recent_event(self._recent_failures)
                self._last_error = type(exc).__name__
            logger.error(
                "flow worker fallback failed error_type=%s", type(exc).__name__
            )
            return
        latency_ms = (time.perf_counter() - started) * 1000.0
        with self._lock:
            self._jobs_processed += 1
            self._latencies_ms.append(latency_ms)
            self._record_slow_job(latency_ms)

    def _record_completion(
        self, state: _WorkerState, latency_ms: float, failed: bool
    ) -> None:
        with self._lock:
            self._latencies_ms.append(latency_ms)
            state.latencies_ms.append(latency_ms)
            if not failed:
                state.processed_total += 1
                self._jobs_processed += 1
            self._record_slow_job(latency_ms)

    def _record_slow_job(self, latency_ms: float) -> None:
        if latency_ms < self.slow_job_ms:
            return
        self._slow_jobs += 1
        self._last_slow_job_at = datetime.now(timezone.utc).isoformat()

    def wait_until_drained(self, timeout_sec: float | None = None) -> bool:
        timeout = (
            self.shutdown_timeout_sec if timeout_sec is None else max(0.0, timeout_sec)
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if not self._queued_jobs and not self._active_flows:
                    return True
            time.sleep(0.01)
        with self._lock:
            return not self._queued_jobs and not self._active_flows

    def close(self, timeout_sec: float | None = None) -> bool:
        with self._lock:
            self._accepting = False
            self._queue_changed.notify_all()
        drained = self.wait_until_drained(timeout_sec)
        self._stop.set()
        with self._queue_changed:
            self._queue_changed.notify_all()
        deadline = time.monotonic() + (
            self.shutdown_timeout_sec if timeout_sec is None else max(0.1, timeout_sec)
        )
        for state in self._workers:
            thread = state.thread
            if thread and thread.is_alive():
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
        return drained

    @staticmethod
    def _record_recent_event(events: deque[tuple[int, int]]) -> None:
        second = int(time.monotonic())
        if events and events[-1][0] == second:
            _, count = events.pop()
            events.append((second, count + 1))
        else:
            events.append((second, 1))

    def stats(self) -> dict[str, Any]:
        with self._lock:
            cutoff = int(time.monotonic() - HEALTH_WINDOW_SEC)
            for events in (self._recent_drops, self._recent_rejections, self._recent_failures):
                while events and events[0][0] < cutoff:
                    events.popleft()
            recent_drops = sum(count for _, count in self._recent_drops)
            recent_rejections = sum(count for _, count in self._recent_rejections)
            recent_failures = sum(count for _, count in self._recent_failures)
            queue_depth = self._queued_jobs
            active_workers = sum(
                1 for state in self._workers if state.thread and state.thread.is_alive()
            )
            utilization = round(queue_depth / self.queue_max_total * 100.0, 2)
            peak_utilization = utilization
            latencies = list(self._latencies_ms)
            pressure_reasons: list[str] = []
            if self.enabled and active_workers < self.worker_count:
                pressure_reasons.append("flow_worker_not_alive")
            if queue_depth and utilization >= 60.0:
                pressure_reasons.append("flow_worker_queue_backlog")
            if utilization >= 80.0:
                pressure_reasons.append("flow_worker_high_utilization")
            if _percentile(latencies, 0.95) >= self.slow_job_ms:
                pressure_reasons.append("flow_worker_slow_jobs")
            if recent_failures:
                pressure_reasons.append("flow_worker_job_failures")
            if recent_drops or recent_rejections:
                pressure_reasons.append("flow_worker_dropped_jobs")

            p95 = _percentile(latencies, 0.95)
            health = "healthy"
            if self.enabled and (
                active_workers < self.worker_count
                or utilization >= 95.0
                or recent_failures >= self.error_threshold
                or recent_drops >= self.error_threshold
                or p95 >= self.slow_job_ms * 5
            ):
                health = "critical"
            elif pressure_reasons:
                health = "degraded"

            per_worker = []
            for state in self._workers:
                worker_latencies = list(state.latencies_ms)
                per_worker.append(
                    {
                        "worker_id": state.worker_id,
                        "worker_alive": bool(state.thread and state.thread.is_alive()),
                        "queue_depth": 0,
                        "busy": state.worker_id in self._active_by_worker,
                        "queue_max": self.queue_max_total,
                        "processed_total": state.processed_total,
                        "failed_total": state.failed_total,
                        "dropped_total": state.dropped_total,
                        "avg_latency_ms": (
                            round(sum(worker_latencies) / len(worker_latencies), 2)
                            if worker_latencies
                            else 0.0
                        ),
                        "p95_latency_ms": _percentile(worker_latencies, 0.95),
                    }
                )

            return {
                "enabled": self.enabled,
                "health": health,
                "worker_count": self.worker_count,
                "active_workers": active_workers,
                "queue_depth_total": queue_depth,
                "high_water_mark": self._queue_high_water,
                "queue_max_total": self.queue_max_total,
                "queue_capacity_shared": True,
                "scheduler": "fair_per_flow",
                "drop_attribution": "shared_queue",
                "unassigned_queue_depth": queue_depth,
                "ready_flows": len(self._ready_flows),
                "busy_workers": len(self._active_by_worker),
                "queued_flows": len(self._flow_queues),
                "largest_flow_backlog": max((len(items) for items in self._flow_queues.values()), default=0),
                "utilization_percent": utilization,
                "peak_worker_utilization_percent": round(peak_utilization, 2),
                "overflow_policy": self.overflow_policy,
                "jobs_received_total": self._jobs_received,
                "jobs_processed_total": self._jobs_processed,
                "jobs_failed_total": self._jobs_failed,
                "jobs_dropped_total": self._jobs_dropped,
                "jobs_rejected_total": self._jobs_rejected,
                "jobs_dropped_recent": recent_drops,
                "jobs_rejected_recent": recent_rejections,
                "jobs_failed_recent": recent_failures,
                "health_window_sec": HEALTH_WINDOW_SEC,
                "unknown_flow_key_total": self._unknown_flow_keys,
                "slow_jobs_total": self._slow_jobs,
                "avg_processing_latency_ms": (
                    round(sum(latencies) / len(latencies), 2) if latencies else 0.0
                ),
                "p95_processing_latency_ms": p95,
                "max_processing_latency_ms": (
                    round(max(latencies), 2) if latencies else 0.0
                ),
                "per_worker": per_worker,
                "last_error": self._last_error,
                "last_drop_reason": self._last_drop_reason,
                "last_slow_job_at": self._last_slow_job_at,
                "pressure_reasons": pressure_reasons,
            }


__all__ = [
    "FlowDispatchKey",
    "FlowWorkerJob",
    "FlowWorkerPool",
    "VALID_OVERFLOW_POLICIES",
]
