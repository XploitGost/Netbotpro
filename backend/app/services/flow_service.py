from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from core.flow_engine import FlowEngine
from core.privacy_redaction import redact_sensitive_data, redact_sensitive_text


class FlowService:
    def __init__(
        self,
        engine: FlowEngine | None = None,
        db_path: str | Path | None = None,
    ) -> None:
        self.engine = engine or FlowEngine()
        self.db_path = Path(
            db_path or os.environ.get("NETBOT_FLOW_DB_PATH", ".runtime/logs/flows.db")
        )
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

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
        snapshot = json.dumps(flow, ensure_ascii=True, default=str)
        with self._connection() as conn:
            conn.execute(
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
                (
                    flow["flow_id"],
                    flow["conversation_id"],
                    flow["first_seen"],
                    flow["last_seen"],
                    flow["app_protocol"],
                    flow["risk_score"],
                    flow["direction"],
                    snapshot,
                ),
            )
        return flow

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
