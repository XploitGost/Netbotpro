from __future__ import annotations

import hashlib
import logging
import os
import queue
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

DEFAULT_WORKER_COUNT = 4
DEFAULT_QUEUE_MAX = 2000
DEFAULT_SHUTDOWN_TIMEOUT_SEC = 5.0
DEFAULT_ERROR_THRESHOLD = 25
DEFAULT_SLOW_JOB_MS = 100.0
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
    queue: queue.Queue[FlowWorkerJob]
    thread: threading.Thread | None = None
    processed_total: int = 0
    failed_total: int = 0
    dropped_total: int = 0
    latencies_ms: deque[float] = field(default_factory=lambda: deque(maxlen=2048))


class FlowWorkerPool:
    """Bounded ordered lanes for parallel packet processing by flow."""

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
        self._stop = threading.Event()
        self._accepting = True
        self._jobs_received = 0
        self._jobs_processed = 0
        self._jobs_failed = 0
        self._jobs_dropped = 0
        self._jobs_rejected = 0
        self._unknown_flow_keys = 0
        self._slow_jobs = 0
        self._latencies_ms: deque[float] = deque(maxlen=4096)
        self._last_error = ""
        self._last_drop_reason = ""
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
        base, remainder = divmod(self.queue_max_total, self.worker_count)
        return [
            _WorkerState(
                worker_id=worker_id,
                queue=queue.Queue(maxsize=base + (1 if worker_id < remainder else 0)),
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
        state = self._workers[self.worker_index_for(packet)]
        return self._enqueue(state, job)

    def _enqueue(self, state: _WorkerState, job: FlowWorkerJob) -> bool:
        try:
            if self.overflow_policy == "block_short":
                state.queue.put(job, timeout=self.block_timeout_sec)
            else:
                state.queue.put_nowait(job)
            return True
        except queue.Full:
            pass

        if self.overflow_policy == "drop_oldest":
            try:
                state.queue.get_nowait()
                state.queue.task_done()
                self._record_drop(state, "flow_worker_queue_full_drop_oldest")
            except queue.Empty:
                pass
            try:
                state.queue.put_nowait(job)
                return True
            except queue.Full:
                self._record_drop(state, "flow_worker_queue_full_after_drop_oldest")
                return False

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
            state.dropped_total += 1
            self._jobs_dropped += 1
            self._last_drop_reason = reason
        logger.warning(
            "flow worker queue pressure; packet job dropped worker_id=%s reason=%s",
            state.worker_id,
            reason,
        )

    def _record_rejection(self, reason: str) -> None:
        with self._lock:
            self._jobs_rejected += 1
            self._last_drop_reason = reason
        logger.warning(
            "flow worker queue pressure; packet job rejected reason=%s", reason
        )

    def _worker_loop(self, state: _WorkerState) -> None:
        while not self._stop.is_set() or not state.queue.empty():
            try:
                job = state.queue.get(timeout=0.1)
            except queue.Empty:
                continue
            started = time.perf_counter()
            failed = False
            try:
                self._processor(job.packet)
            except Exception as exc:  # pragma: no cover - behavior asserted via metrics
                failed = True
                with self._lock:
                    state.failed_total += 1
                    self._jobs_failed += 1
                    self._last_error = type(exc).__name__
                logger.error(
                    "flow worker job failed worker_id=%s error_type=%s",
                    state.worker_id,
                    type(exc).__name__,
                )
            finally:
                latency_ms = (time.perf_counter() - started) * 1000.0
                self._record_completion(state, latency_ms, failed)
                state.queue.task_done()

    def _process_inline(self, packet: dict[str, Any]) -> None:
        started = time.perf_counter()
        try:
            self._processor(dict(packet))
        except Exception as exc:
            with self._lock:
                self._jobs_failed += 1
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
            if all(state.queue.unfinished_tasks == 0 for state in self._workers):
                return True
            time.sleep(0.01)
        return all(state.queue.unfinished_tasks == 0 for state in self._workers)

    def close(self, timeout_sec: float | None = None) -> bool:
        with self._lock:
            self._accepting = False
        drained = self.wait_until_drained(timeout_sec)
        self._stop.set()
        deadline = time.monotonic() + (
            self.shutdown_timeout_sec if timeout_sec is None else max(0.1, timeout_sec)
        )
        for state in self._workers:
            thread = state.thread
            if thread and thread.is_alive():
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
        return drained

    def stats(self) -> dict[str, Any]:
        with self._lock:
            queue_depth = sum(state.queue.qsize() for state in self._workers)
            active_workers = sum(
                1 for state in self._workers if state.thread and state.thread.is_alive()
            )
            utilization = round(queue_depth / self.queue_max_total * 100.0, 2)
            latencies = list(self._latencies_ms)
            pressure_reasons: list[str] = []
            if self.enabled and active_workers < self.worker_count:
                pressure_reasons.append("flow_worker_not_alive")
            if queue_depth and utilization >= 60.0:
                pressure_reasons.append("flow_worker_queue_backlog")
            if utilization >= 80.0:
                pressure_reasons.append("flow_worker_high_utilization")
            if self._slow_jobs:
                pressure_reasons.append("flow_worker_slow_jobs")
            if self._jobs_failed:
                pressure_reasons.append("flow_worker_job_failures")
            if self._jobs_dropped or self._jobs_rejected:
                pressure_reasons.append("flow_worker_dropped_jobs")

            p95 = _percentile(latencies, 0.95)
            health = "healthy"
            if self.enabled and (
                active_workers < self.worker_count
                or utilization >= 95.0
                or self._jobs_failed >= self.error_threshold
                or self._jobs_dropped >= self.error_threshold
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
                        "queue_depth": state.queue.qsize(),
                        "queue_max": state.queue.maxsize,
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
                "queue_max_total": self.queue_max_total,
                "utilization_percent": utilization,
                "overflow_policy": self.overflow_policy,
                "jobs_received_total": self._jobs_received,
                "jobs_processed_total": self._jobs_processed,
                "jobs_failed_total": self._jobs_failed,
                "jobs_dropped_total": self._jobs_dropped,
                "jobs_rejected_total": self._jobs_rejected,
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
