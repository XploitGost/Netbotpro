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
    ) -> None:
        self.engine = engine or FlowEngine()
        self.db_path = Path(
            db_path or os.environ.get("NETBOT_FLOW_DB_PATH", ".runtime/logs/flows.db")
        )
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        self._batch_writer = (
            _FlowSnapshotBatchWriter(self) if batch_persistence else None
        )

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

    def ingest(
        self, packet: dict[str, Any], alerts: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        flow = self.engine.ingest(packet, alerts)
        flow = redact_sensitive_data(flow)
        if self._batch_writer is not None:
            self._batch_writer.enqueue(flow)
        else:
            self._write_snapshots([flow])
        return flow

    def _write_snapshots(self, flows: list[dict[str, Any]]) -> None:
        if not flows:
            return
        with self._connection() as conn:
            conn.executemany(
                """
                INSERT INTO flows (
                    flow_id, conversation_id, first_seen, last_seen,
                    app_protocol, risk_score, direction, snapshot_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(flow_id) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    app_protocol=excluded.app_protocol,
                    risk_score=excluded.risk_score,
                    direction=excluded.direction,
                    snapshot_json=excluded.snapshot_json
                """,
                [
                    (
                        flow["flow_id"],
                        flow["conversation_id"],
                        flow["first_seen"],
                        flow["last_seen"],
                        flow["app_protocol"],
                        flow["risk_score"],
                        flow["direction"],
                        json.dumps(flow, ensure_ascii=True, default=str),
                    )
                    for flow in flows
                ],
            )

    def persistence_stats(self) -> dict[str, Any]:
        if self._batch_writer is None:
            return {"enabled": False}
        return self._batch_writer.stats()

    def close(self, timeout_sec: float = 5.0) -> None:
        if self._batch_writer is not None:
            self._batch_writer.close(timeout_sec=timeout_sec)

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
        return redact_sensitive_data(self.engine.summary())

    def reset(self) -> None:
        self.engine.reset()

    def protocols_summary(self) -> dict[str, Any]:
        flows = self.list_flows(limit=500)
        protocols: dict[str, dict[str, Any]] = {}
        for flow in flows:
            name = str(flow.get("app_protocol") or "UNKNOWN")
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
        summary = self.summary()
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
