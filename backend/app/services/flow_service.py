from __future__ import annotations

import csv
import io
import json
import logging
import os
import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from core.flow_engine import FlowEngine
from core.privacy_redaction import redact_sensitive_data, redact_sensitive_text

logger = logging.getLogger(__name__)


class FlowService:
    def __init__(
        self,
        engine: FlowEngine | None = None,
        db_path: str | Path | None = None,
        batch_persistence: bool = False,
        persistent_writer: bool = False,
        memory_compaction: bool | None = None,
    ) -> None:
        self.engine = engine or FlowEngine()
        self.db_path = Path(
            db_path or os.environ.get("NETBOT_FLOW_DB_PATH", ".runtime/logs/flows.db")
        )
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._snapshot_lock = threading.RLock()
        self._storage_lock = threading.Lock()
        self._storage_samples = deque(maxlen=512)
        self._persistent_writer = persistent_writer or batch_persistence
        self._snapshot_connection: sqlite3.Connection | None = None
        self._init_schema()
        self._batch_writer = (
            _FlowSnapshotBatchWriter(self) if batch_persistence else None
        )
        self._memory_stop = threading.Event()
        self._memory_lock = threading.Lock()
        self._memory_error = ''
        self._memory_errors = 0
        self._memory_thread = None
        self._hot_target = 2048
        self._cold_after = 120.0
        try:
            self._hot_target = max(64, min(100000, int(os.environ.get('NETBOT_FLOW_HOT_TARGET', '2048'))))
            self._cold_after = max(1.0, min(86400.0, float(os.environ.get('NETBOT_FLOW_COLD_AFTER_SECONDS', '120'))))
        except (TypeError, ValueError):
            pass
        enabled = self._persistent_writer if memory_compaction is None else memory_compaction
        if enabled:
            self._memory_thread = threading.Thread(target=self._compact_memory, daemon=True,
                                                   name='netbotpro-flow-memory')
            self._memory_thread.start()

    def _compact_memory(self):
        while not self._memory_stop.wait(1.0):
            try:
                self.engine.compact_idle(hot_target=self._hot_target, idle_seconds=self._cold_after, batch_size=16)
                with self._memory_lock:
                    self._memory_error = ''
            except Exception as exc:
                with self._memory_lock:
                    self._memory_errors += 1
                    self._memory_error = type(exc).__name__

    def memory_stats(self):
        metrics = self.engine.memory_stats()
        with self._memory_lock:
            error, errors = self._memory_error, self._memory_errors
        reasons = []
        if metrics['hot_flows'] > self._hot_target * 2:
            reasons.append('flow_memory_hot_pressure')
        if error:
            reasons.append('flow_memory_compaction_error')
        return dict(metrics, enabled=self._memory_thread is not None,
                    worker_alive=bool(self._memory_thread and self._memory_thread.is_alive()),
                    hot_target=self._hot_target, cold_after_seconds=self._cold_after,
                    errors_total=errors, last_error=error, pressure_reasons=reasons,
                    health='degraded' if reasons else 'healthy')

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    @contextmanager
    def _connection(self):
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    flow_id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    app_protocol TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    direction TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL
                )
                """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(last_seen)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_flows_protocol ON flows(app_protocol)"
            )

    @contextmanager
    def _snapshot_transaction(self, timings=None):
        timings = timings if timings is not None else {}
        if not self._persistent_writer:
            with self._connection() as connection:
                yield connection
            return
        # Keep the WAL writer open between batches; serialize cross-thread use.
        waiting = time.perf_counter()
        with self._snapshot_lock:
            timings['lock_wait'] = (time.perf_counter() - waiting) * 1000
            if self._snapshot_connection is None:
                self._snapshot_connection = sqlite3.connect(
                    self.db_path, check_same_thread=False
                )
            with self._snapshot_connection:
                yield self._snapshot_connection
                committing = time.perf_counter()
            timings['commit'] = (time.perf_counter() - committing) * 1000

    def ingest(
        self,
        packet: dict[str, Any],
        alerts: list[dict[str, Any]] | None = None,
        *,
        persist: bool = True,
    ) -> dict[str, Any]:
        flow = self.engine.ingest(packet, alerts, redact_snapshot=True)
        if not persist:
            return flow
        if self._batch_writer is not None:
            self._batch_writer.enqueue(flow)
        else:
            self._write_snapshots([flow])
        return flow

    def write_snapshots(self, flows: list[dict[str, Any]]) -> None:
        """Persist already-redacted flow snapshots in one SQLite transaction."""
        latest = {
            str(flow["flow_id"]): flow
            for flow in flows
            if flow.get("flow_id")
        }
        self._write_snapshots([redact_sensitive_data(flow) for flow in latest.values()])

    def ingest_live(self, packet: dict[str, Any], alerts=None) -> dict[str, Any]:
        return self.engine.ingest(
            packet, alerts, redact_snapshot=True, live_summary=True
        )

    def ingest_for_analysis(self, packet: dict[str, Any], alerts=None) -> dict[str, Any]:
        """Detached internal summary; public writers must redact at their boundary."""
        return self.engine.ingest(packet, alerts, live_summary=True)

    def write_live_snapshots(self, references: list[dict[str, Any]]) -> None:
        # Resolve once per flow per batch, not once per captured packet.
        identifiers = dict.fromkeys(str(row["flow_id"]) for row in references if row.get("flow_id"))
        started = time.perf_counter()
        snapshots = self.engine.snapshot_flows(list(identifiers))
        snapshot_ms = (time.perf_counter() - started) * 1000
        self._write_snapshots(snapshots, snapshot_ms=snapshot_ms)

    def _write_snapshots(self, flows: list[dict[str, Any]], *, snapshot_ms: float = 0.0) -> None:
        if not flows:
            return
        started = time.perf_counter()
        rows = [(flow['flow_id'], flow['conversation_id'], flow['first_seen'], flow['last_seen'],
                 flow['app_protocol'], flow['risk_score'], flow['direction'],
                 json.dumps(flow, ensure_ascii=True, default=str)) for flow in flows]
        serialization_ms = (time.perf_counter() - started) * 1000
        started = time.perf_counter()
        timings = {}
        with self._snapshot_transaction(timings) as conn:
            executing = time.perf_counter()
            statement = """
                INSERT INTO flows (
                    flow_id, conversation_id, first_seen, last_seen,
                    app_protocol, risk_score, direction, snapshot_json
                ) VALUES {values}
                ON CONFLICT(flow_id) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    app_protocol=excluded.app_protocol,
                    risk_score=excluded.risk_score,
                    direction=excluded.direction,
                    snapshot_json=excluded.snapshot_json
                WHERE flows.snapshot_json IS NOT excluded.snapshot_json
                   OR flows.last_seen IS NOT excluded.last_seen
                   OR flows.app_protocol IS NOT excluded.app_protocol
                   OR flows.risk_score IS NOT excluded.risk_score
                   OR flows.direction IS NOT excluded.direction
                """
            # Fewer SQLite calls reduce GIL hand-offs under concurrent analysis.
            # 100 rows stay below SQLite's historical 999-variable limit.
            for offset in range(0, len(rows), 100):
                chunk = rows[offset:offset + 100]
                values = ','.join(['(?,?,?,?,?,?,?,?)'] * len(chunk))
                conn.execute(statement.format(values=values),
                             [value for row in chunk for value in row])
            timings['sql'] = (time.perf_counter() - executing) * 1000
        transaction_ms = (time.perf_counter() - started) * 1000
        with self._storage_lock:
            self._storage_samples.append((time.monotonic(), snapshot_ms, serialization_ms, transaction_ms, len(rows), timings))

    def storage_metrics(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._storage_lock:
            samples = [row for row in self._storage_samples if now - row[0] <= 60]
        metrics = {'window_seconds':60, 'batches':len(samples)}
        for index, name in enumerate(('snapshot_build', 'serialization', 'transaction'), 1):
            values = sorted(row[index] for row in samples)
            metrics[f'{name}_ms_p95'] = round(values[min(len(values)-1, int(len(values)*0.95))], 2) if values else 0.0
        metrics['last_batch_flows'] = samples[-1][4] if samples else 0
        for name in ('lock_wait', 'sql', 'commit'):
            values = sorted(row[5][name] for row in samples if name in row[5])
            metrics[f'{name}_ms_p95'] = round(values[min(len(values)-1, int(len(values)*0.95))], 2) if values else None
        return metrics

    def persistence_stats(self) -> dict[str, Any]:
        if self._batch_writer is None:
            return {"enabled": False}
        return self._batch_writer.stats()

    def close(self, timeout_sec: float = 5.0) -> None:
        self._memory_stop.set()
        if self._memory_thread is not None:
            self._memory_thread.join(max(1, timeout_sec))
            if self._memory_thread.is_alive():
                raise RuntimeError('Flow memory worker did not stop')
        if self._batch_writer is not None:
            self._batch_writer.close(timeout_sec=timeout_sec)
        with self._snapshot_lock:
            if self._snapshot_connection is not None:
                self._snapshot_connection.close()
                self._snapshot_connection = None

    def list_flows(self, **filters: Any) -> list[dict[str, Any]]:
        return redact_sensitive_data(self.engine.list_flows(**filters))

    def get_flow(self, flow_id: str) -> dict[str, Any] | None:
        return redact_sensitive_data(self.engine.get_flow(flow_id))

    def timeline(self, flow_id: str) -> list[dict[str, Any]]:
        return redact_sensitive_data(self.engine.timeline(flow_id))

    def conversations(self) -> list[dict[str, Any]]:
        return redact_sensitive_data(self.engine.conversations())

    def get_conversation(self, conversation_id: str) -> dict[str, Any] | None:
        return redact_sensitive_data(self.engine.get_conversation(conversation_id))

    def summary(self) -> dict[str, Any]:
        return redact_sensitive_data(self.engine.summary(compact_top=True))

    def monitoring_summary(self) -> dict[str, Any]:
        return self.engine.monitoring_summary()

    def reset(self) -> None:
        self.engine.reset()

    def protocols_summary(self) -> dict[str, Any]:
        flows = self.list_flows(limit=500)
        protocols: dict[str, dict[str, Any]] = {}
        for flow in flows:
            name = str(flow.get("app_protocol") or "UNKNOWN")
            if name == "UNKNOWN":
                name = str(flow.get("transport") or "OTHER")
            row = protocols.setdefault(
                name,
                {
                    "protocol": name,
                    "packet_count": 0,
                    "flow_count": 0,
                    "bytes_total": 0,
                    "alert_count": 0,
                    "expert_warning_count": 0,
                    "risk_total": 0,
                    "risk_max": 0,
                },
            )
            risk = int(flow.get("risk_score") or 0)
            row["packet_count"] += int(flow.get("packets_count") or 0)
            row["flow_count"] += 1
            row["bytes_total"] += int(flow.get("bytes_total") or 0)
            row["alert_count"] += len(flow.get("related_alert_ids") or [])
            row["risk_total"] += risk
            row["risk_max"] = max(row["risk_max"], risk)
        items = []
        for row in protocols.values():
            row["risk_avg"] = round(row.pop("risk_total") / row["flow_count"], 2)
            items.append(row)
        items.sort(key=lambda row: row["packet_count"], reverse=True)
        return redact_sensitive_data(
            {
                "total_packets": sum(row["packet_count"] for row in items),
                "total_flows": len(flows),
                "protocols": items,
            }
        )

    def report(self) -> dict[str, Any]:
        summary = redact_sensitive_data(self.engine.summary())
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_flows": summary["total_flows"],
            "top_protocols": summary["top_protocols"],
            "top_risky_flows": summary["top_risky_flows"],
            "top_destinations": summary["top_destinations"],
            "protocol_distribution": summary["top_protocols"],
            "risk_distribution": summary["risk_distribution"],
            "recommended_actions": [
                "Review high and critical risk flows.",
                "Validate unusual destinations and protocols.",
                "Keep capture and exports within authorized scope.",
            ],
        }

    def report_csv(self) -> str:
        output = io.StringIO()
        fields = [
            "flow_id",
            "app_protocol",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "direction",
            "packets_count",
            "bytes_total",
            "risk_score",
            "risk_level",
            "risk_reasons",
        ]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for flow in self.list_flows(limit=500):
            row = dict(flow)
            row["risk_reasons"] = redact_sensitive_text(
                "; ".join(flow.get("risk_reasons") or [])
            )
            writer.writerow(row)
        return output.getvalue()

    def cleanup_history(self, retention_days: int | None = None) -> int:
        configured = retention_days or int(
            os.environ.get("NETBOT_FLOW_HISTORY_RETENTION_DAYS", "7")
        )
        days = max(1, min(int(configured), 365))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._connection() as conn:
            cursor = conn.execute("DELETE FROM flows WHERE last_seen < ?", (cutoff,))
            return int(cursor.rowcount or 0)


__all__ = ["FlowService"]


class _FlowSnapshotBatchWriter:
    def __init__(self, service: FlowService) -> None:
        self._service = service
        self._batch_size = max(
            1, int(os.environ.get("NETBOT_FLOW_PERSIST_BATCH_SIZE", "100"))
        )
        self._flush_interval = max(
            0.05, float(os.environ.get("NETBOT_FLOW_PERSIST_FLUSH_INTERVAL_SEC", "0.5"))
        )
        self._max_size = max(
            1, int(os.environ.get("NETBOT_FLOW_PERSIST_QUEUE_MAX_SIZE", "2000"))
        )
        self._max_retries = max(
            0, int(os.environ.get("NETBOT_FLOW_PERSIST_MAX_RETRIES", "3"))
        )
        self._retry_backoff_sec = max(
            0.0, float(os.environ.get("NETBOT_FLOW_PERSIST_RETRY_BACKOFF_SEC", "0.1"))
        )
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=self._max_size)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._accepted = 0
        self._dropped = 0
        self._persisted = 0
        self._batches = 0
        self._failed = 0
        self._retries = 0
        self._high_water = 0
        self._latency_total_ms = 0.0
        self._worker = threading.Thread(
            target=self._run,
            name="netbotpro-flow-persistence",
            daemon=True,
        )
        self._worker.start()

    def enqueue(self, flow: dict[str, Any]) -> None:
        try:
            self._queue.put_nowait(flow)
            with self._lock:
                self._accepted += 1
                self._high_water = max(self._high_water, self._queue.qsize())
        except queue.Full:
            with self._lock:
                self._dropped += 1
            logger.warning("flow persistence queue full; snapshot dropped")

    def _run(self) -> None:
        while not self._stop.is_set() or not self._queue.empty():
            try:
                first = self._queue.get(timeout=self._flush_interval)
            except queue.Empty:
                continue
            rows = [first]
            deadline = time.monotonic() + self._flush_interval
            while len(rows) < self._batch_size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    rows.append(self._queue.get(timeout=remaining))
                except queue.Empty:
                    break

            # A flow can be updated repeatedly inside one window; only its latest
            # redacted snapshot needs to reach SQLite.
            latest = {row["flow_id"]: row for row in rows}
            started = time.perf_counter()
            try:
                retries = self._write_with_retry(list(latest.values()))
                latency_ms = (time.perf_counter() - started) * 1000.0
                with self._lock:
                    self._persisted += len(latest)
                    self._batches += 1
                    self._latency_total_ms += latency_ms
                    self._retries += retries
            except Exception as exc:
                with self._lock:
                    self._failed += len(latest)
                logger.error(
                    "flow persistence batch failed error_type=%s rows=%s",
                    type(exc).__name__,
                    len(latest),
                )
            finally:
                for _ in rows:
                    self._queue.task_done()

    def _write_with_retry(self, rows: list[dict[str, Any]]) -> int:
        retries = 0
        while True:
            try:
                self._service._write_snapshots(rows)
                return retries
            except Exception:
                if retries >= self._max_retries or self._stop.is_set():
                    raise
                delay = self._retry_backoff_sec * (2**retries)
                retries += 1
                logger.warning(
                    "flow persistence retry attempt=%s delay_ms=%.0f",
                    retries,
                    delay * 1000.0,
                )
                if self._stop.wait(delay):
                    raise

    def stats(self) -> dict[str, Any]:
        with self._lock:
            depth = self._queue.qsize()
            return {
                "enabled": True,
                "queue_size": depth,
                "max_size": self._max_size,
                "utilization_percent": round(depth / self._max_size * 100.0, 2),
                "accepted_total": self._accepted,
                "dropped_total": self._dropped,
                "persisted_total": self._persisted,
                "failed_total": self._failed,
                "retries_total": self._retries,
                "flush_batches": self._batches,
                "avg_flush_ms": (
                    round(self._latency_total_ms / self._batches, 2)
                    if self._batches
                    else 0.0
                ),
                "high_water_mark": self._high_water,
                "worker_alive": self._worker.is_alive(),
            }

    def close(self, timeout_sec: float = 5.0) -> None:
        self._stop.set()
        self._worker.join(timeout=max(0.1, timeout_sec))
