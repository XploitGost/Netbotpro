from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.services.redaction import redact_sensitive_text

ensure_project_root_on_path()

from log_manager import LOG_DIR  # noqa: E402

DEFAULT_AGENT_OFFLINE_AFTER_SECONDS = 90
_MAX_HISTORY_LIMIT = 500
SAFE_NODE_TYPES = {"server", "sensor", "agent"}
SAFE_AGENT_CAPABILITIES = {
    "telemetry",
    "health",
    "capture_status",
    "alerts_summary",
    "flows_summary",
    "redacted_flow_metadata",
    "redacted_service_metadata",
    "local_capture_metadata",
    "offline_pcap_metadata",
    "demo",
}
FORBIDDEN_NODE_CAPABILITIES = {
    "remote_shell",
    "command_execution",
    "command_control",
    "file_collection",
    "raw_payload_forwarding",
    "raw_packet_forwarding",
    "raw_pcap_forwarding",
    "raw_payload",
    "raw_packet",
    "raw_pcap",
    "credential_access",
    "tls_decryption",
    "mitm",
}
_SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "credential",
    "authorization",
    "cookie",
    "session",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _offline_after_seconds() -> int:
    raw = os.environ.get("NETBOT_AGENT_OFFLINE_AFTER_SECONDS", "").strip()
    try:
        return max(5, min(86400, int(raw)))
    except (TypeError, ValueError):
        return DEFAULT_AGENT_OFFLINE_AFTER_SECONDS


def _range_start(range_name: str) -> str:
    text = str(range_name or "24h").strip().lower()
    now = datetime.now(timezone.utc)
    if text == "1h":
        return (now - timedelta(hours=1)).isoformat()
    if text == "7d":
        return (now - timedelta(days=7)).isoformat()
    if text == "30d":
        return (now - timedelta(days=30)).isoformat()
    return (now - timedelta(hours=24)).isoformat()


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            key_text = str(key)
            if any(marker in key_text.lower() for marker in _SENSITIVE_KEYS):
                cleaned[key_text] = "[REDACTED]"
            else:
                cleaned[key_text] = _redact(item)
        return cleaned
    if isinstance(value, list):
        return [_redact(item) for item in value[:200]]
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value


def normalize_node_type(value: Any) -> str:
    node_type = str(value or "agent").strip().lower()
    if node_type not in SAFE_NODE_TYPES:
        raise ValueError("node_type must be server, sensor, or agent")
    return node_type


def normalize_capabilities(value: Any) -> list[str]:
    items = value if isinstance(value, list) else []
    capabilities: list[str] = []
    for item in items[:64]:
        capability = str(item or "").strip().lower()
        if not capability:
            continue
        if capability in FORBIDDEN_NODE_CAPABILITIES:
            raise ValueError(f"Forbidden node capability: {capability}")
        if capability in SAFE_AGENT_CAPABILITIES and capability not in capabilities:
            capabilities.append(capability)
    return capabilities


def _count(alerts: dict[str, Any], *keys: str) -> int:
    for key in keys:
        value = alerts.get(key)
        if value is not None:
            try:
                return max(0, int(value))
            except (TypeError, ValueError):
                return 0
    return 0


def compute_agent_risk(
    *,
    status: str = "online",
    health: dict[str, Any] | None = None,
    alerts: dict[str, Any] | None = None,
    capture: dict[str, Any] | None = None,
    flows: dict[str, Any] | None = None,
) -> dict[str, Any]:
    health = health or {}
    alerts = alerts or {}
    capture = capture or {}
    flows = flows or {}

    critical = _count(alerts, "critical_count", "critical")
    high = _count(alerts, "high_count", "high")
    medium = _count(alerts, "medium_count", "medium")
    low = _count(alerts, "low_count", "low")

    score = critical * 35 + high * 20 + medium * 10 + low * 4
    for key in ("cpu_percent", "memory_percent", "disk_percent"):
        try:
            value = float(health.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value >= 95:
            score += 15
        elif value >= 85:
            score += 10
        elif value >= 75:
            score += 5

    if capture.get("last_capture_error"):
        score += 15
    if status == "offline":
        score += 20

    traffic_count = (
        flows.get("flow_count")
        or flows.get("total_flows")
        or flows.get("packet_count")
        or flows.get("total_packets")
        or 0
    )
    try:
        if int(traffic_count) >= 10000:
            score += 10
    except (TypeError, ValueError):
        pass

    score = max(0, min(100, int(score)))
    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    else:
        severity = "low"
    return {
        "score": score,
        "severity": severity,
        "critical_alerts": critical,
        "high_alerts": high,
        "medium_alerts": medium,
        "low_alerts": low,
    }


def _agent_status(last_seen: str | None, fallback: str = "online") -> str:
    parsed = _parse_time(last_seen)
    if not parsed:
        return fallback or "unknown"
    age = (datetime.now(timezone.utc) - parsed).total_seconds()
    return "offline" if age > _offline_after_seconds() else fallback or "online"


def _agent_public(record: dict[str, Any]) -> dict[str, Any]:
    item = dict(record)
    item.pop("token", None)
    item.pop("token_hash", None)
    item["status"] = _agent_status(
        str(item.get("last_seen") or ""), item.get("status", "online")
    )
    return _redact(item)


class AgentRegistry:
    def __init__(self, storage_path: str | Path | None = None) -> None:
        default_storage = LOG_DIR / "agents.db"
        self.storage_path = Path(storage_path) if storage_path else default_storage
        self._use_jsonl = self.storage_path.suffix.lower() == ".jsonl"
        self._lock = threading.Lock()
        self._agents: dict[str, dict[str, Any]] = {}
        self._telemetry: dict[str, list[dict[str, Any]]] = {}
        if self._use_jsonl:
            self._load_jsonl()
        else:
            self._init_sqlite()
            self._load_sqlite_cache()

    def _connect(self) -> sqlite3.Connection:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.storage_path)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _connection(self):
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_sqlite(self) -> None:
        with self._connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    hostname TEXT,
                    display_name TEXT,
                    os TEXT,
                    platform TEXT,
                    os_version TEXT,
                    machine TEXT,
                    agent_version TEXT,
                    capabilities_json TEXT NOT NULL DEFAULT '[]',
                    token_hash TEXT,
                    status TEXT NOT NULL DEFAULT 'online',
                    registered_at TEXT NOT NULL,
                    last_seen TEXT,
                    last_telemetry_at TEXT,
                    last_telemetry_json TEXT,
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    risk_severity TEXT NOT NULL DEFAULT 'low'
                );
                CREATE TABLE IF NOT EXISTS agent_heartbeats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agent_telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agent_health_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    cpu_percent REAL,
                    memory_percent REAL,
                    disk_percent REAL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agent_alert_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    total_alerts INTEGER NOT NULL DEFAULT 0,
                    critical_count INTEGER NOT NULL DEFAULT 0,
                    high_count INTEGER NOT NULL DEFAULT 0,
                    medium_count INTEGER NOT NULL DEFAULT 0,
                    low_count INTEGER NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agent_flow_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    flow_count INTEGER NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agent_risk_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_agent_heartbeats_agent_time
                    ON agent_heartbeats(agent_id, received_at);
                CREATE INDEX IF NOT EXISTS idx_agent_telemetry_agent_time
                    ON agent_telemetry(agent_id, received_at);
                CREATE INDEX IF NOT EXISTS idx_agent_health_agent_time
                    ON agent_health_snapshots(agent_id, received_at);
                CREATE INDEX IF NOT EXISTS idx_agent_alert_agent_time
                    ON agent_alert_snapshots(agent_id, received_at);
                CREATE INDEX IF NOT EXISTS idx_agent_flow_agent_time
                    ON agent_flow_snapshots(agent_id, received_at);
                CREATE INDEX IF NOT EXISTS idx_agent_risk_agent_time
                    ON agent_risk_snapshots(agent_id, received_at);
                """)

    def _load_sqlite_cache(self) -> None:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM agents").fetchall()
            self._agents = {row["agent_id"]: self._row_to_agent(row) for row in rows}
            self._telemetry = {}
            telemetry_rows = conn.execute("""
                SELECT agent_id, payload_json
                FROM agent_telemetry
                ORDER BY received_at DESC
                LIMIT 1000
                """).fetchall()
        for row in telemetry_rows:
            item = _json_loads(row["payload_json"], {})
            self._telemetry.setdefault(row["agent_id"], []).append(item)
        for agent_id, items in self._telemetry.items():
            self._telemetry[agent_id] = list(reversed(items[-50:]))

    def _row_to_agent(self, row: sqlite3.Row) -> dict[str, Any]:
        record = {
            "agent_id": row["agent_id"],
            "hostname": row["hostname"] or "",
            "display_name": row["display_name"] or row["agent_id"],
            "os": row["os"] or "",
            "platform": row["platform"] or "",
            "os_version": row["os_version"] or "",
            "machine": row["machine"] or "",
            "agent_version": row["agent_version"] or "",
            "capabilities": _json_loads(row["capabilities_json"], []),
            "token_hash": row["token_hash"] or "",
            "status": row["status"] or "online",
            "registered_at": row["registered_at"],
            "last_seen": row["last_seen"] or "",
            "last_telemetry_at": row["last_telemetry_at"] or "",
            "last_telemetry": _json_loads(row["last_telemetry_json"], {}),
            "risk": {
                "score": int(row["risk_score"] or 0),
                "severity": row["risk_severity"] or "low",
            },
        }
        return record

    def _load_jsonl(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            for line in self.storage_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                event = json.loads(line)
                event_type = event.get("type")
                agent_id = str(event.get("agent_id") or "")
                if not agent_id:
                    continue
                if event_type == "agent":
                    self._agents[agent_id] = dict(event.get("record") or {})
                elif event_type == "telemetry":
                    self._telemetry.setdefault(agent_id, []).append(
                        dict(event.get("payload") or {})
                    )
                    self._telemetry[agent_id] = self._telemetry[agent_id][-50:]
        except Exception:
            self._agents = {}
            self._telemetry = {}

    def _append_jsonl(self, event: dict[str, Any]) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        with self.storage_path.open("a", encoding="utf-8") as handle:
            handle.write(_json_dumps(event) + "\n")

    def register(self, payload: dict[str, Any], token: str) -> dict[str, Any]:
        agent_id = str(payload.get("agent_id") or "").strip()
        if not agent_id:
            raise ValueError("agent_id is required")
        if not token:
            raise PermissionError("agent token is required")
        configured_token = os.environ.get("NETBOT_AGENT_TOKEN", "").strip()
        if configured_token and not hmac.compare_digest(configured_token, token):
            raise PermissionError("invalid agent token")
        node_type = normalize_node_type(payload.get("node_type") or payload.get("type"))
        capabilities = normalize_capabilities(payload.get("capabilities") or [])
        now = _now()
        with self._lock:
            existing = self._agents.get(agent_id, {})
            record = {
                **existing,
                "agent_id": agent_id,
                "node_id": agent_id,
                "node_name": redact_sensitive_text(
                    str(
                        payload.get("node_name")
                        or payload.get("display_name")
                        or payload.get("hostname")
                        or agent_id
                    )
                ),
                "node_type": node_type,
                "profile": redact_sensitive_text(
                    str(payload.get("profile") or node_type)
                ),
                "version": redact_sensitive_text(
                    str(payload.get("version") or payload.get("agent_version") or "")
                ),
                "metadata_redacted": True,
                "hostname": redact_sensitive_text(str(payload.get("hostname") or "")),
                "display_name": redact_sensitive_text(
                    str(
                        payload.get("display_name")
                        or payload.get("hostname")
                        or agent_id
                    )
                ),
                "os": redact_sensitive_text(str(payload.get("os") or "")),
                "platform": redact_sensitive_text(str(payload.get("platform") or "")),
                "os_version": redact_sensitive_text(
                    str(payload.get("os_version") or "")
                ),
                "machine": redact_sensitive_text(str(payload.get("machine") or "")),
                "agent_version": redact_sensitive_text(
                    str(payload.get("agent_version") or "")
                ),
                "capabilities": capabilities,
                "token_hash": _token_digest(token),
                "status": "online",
                "registered_at": existing.get("registered_at") or now,
                "last_seen": now,
                "risk": existing.get("risk") or {"score": 0, "severity": "low"},
            }
            self._agents[agent_id] = record
            if self._use_jsonl:
                self._append_jsonl(
                    {"type": "agent", "agent_id": agent_id, "record": record}
                )
            else:
                self._upsert_agent(record)
            return _agent_public(record)

    def _upsert_agent(self, record: dict[str, Any]) -> None:
        risk = record.get("risk") or {}
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO agents (
                    agent_id, hostname, display_name, os, platform, os_version,
                    machine, agent_version, capabilities_json, token_hash, status,
                    registered_at, last_seen, last_telemetry_at, last_telemetry_json,
                    risk_score, risk_severity
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    display_name=excluded.display_name,
                    os=excluded.os,
                    platform=excluded.platform,
                    os_version=excluded.os_version,
                    machine=excluded.machine,
                    agent_version=excluded.agent_version,
                    capabilities_json=excluded.capabilities_json,
                    token_hash=excluded.token_hash,
                    status=excluded.status,
                    last_seen=excluded.last_seen,
                    last_telemetry_at=excluded.last_telemetry_at,
                    last_telemetry_json=excluded.last_telemetry_json,
                    risk_score=excluded.risk_score,
                    risk_severity=excluded.risk_severity
                """,
                (
                    record["agent_id"],
                    record.get("hostname", ""),
                    record.get("display_name", record["agent_id"]),
                    record.get("os", ""),
                    record.get("platform", ""),
                    record.get("os_version", ""),
                    record.get("machine", ""),
                    record.get("agent_version", ""),
                    _json_dumps(record.get("capabilities", [])),
                    record.get("token_hash", ""),
                    record.get("status", "online"),
                    record.get("registered_at") or _now(),
                    record.get("last_seen") or "",
                    record.get("last_telemetry_at") or "",
                    _json_dumps(record.get("last_telemetry") or {}),
                    int(risk.get("score") or 0),
                    str(risk.get("severity") or "low"),
                ),
            )

    def verify(self, agent_id: str, token: str) -> bool:
        agent = self._agents.get(agent_id)
        if not agent or not token:
            return False
        configured_token = os.environ.get("NETBOT_AGENT_TOKEN", "").strip()
        if configured_token:
            return hmac.compare_digest(configured_token, token)
        expected_hash = str(agent.get("token_hash") or "")
        if expected_hash:
            return hmac.compare_digest(expected_hash, _token_digest(token))
        legacy_token = str(agent.get("token") or "")
        return bool(legacy_token) and hmac.compare_digest(legacy_token, token)

    def heartbeat(self, agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if agent_id not in self._agents:
                raise KeyError(agent_id)
            received_at = _now()
            cleaned = _redact(payload)
            record = dict(self._agents[agent_id])
            record["last_seen"] = received_at
            record["status"] = redact_sensitive_text(
                str(cleaned.get("status") or "online")
            )
            self._agents[agent_id] = record
            if self._use_jsonl:
                self._append_jsonl(
                    {"type": "agent", "agent_id": agent_id, "record": record}
                )
            else:
                self._upsert_agent(record)
                with self._connection() as conn:
                    conn.execute(
                        """
                        INSERT INTO agent_heartbeats(agent_id, received_at, status, payload_json)
                        VALUES (?, ?, ?, ?)
                        """,
                        (agent_id, received_at, record["status"], _json_dumps(cleaned)),
                    )
            return _agent_public(record)

    def telemetry(self, agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if agent_id not in self._agents:
                raise KeyError(agent_id)
            received_at = _now()
            cleaned = _redact(
                {**payload, "agent_id": agent_id, "received_at": received_at}
            )
            health = (
                cleaned.get("health") if isinstance(cleaned.get("health"), dict) else {}
            )
            alerts = (
                cleaned.get("alerts_summary")
                if isinstance(cleaned.get("alerts_summary"), dict)
                else {}
            )
            flows = (
                cleaned.get("flows_summary")
                if isinstance(cleaned.get("flows_summary"), dict)
                else {}
            )
            capture = (
                cleaned.get("capture")
                if isinstance(cleaned.get("capture"), dict)
                else {}
            )
            record = dict(self._agents[agent_id])
            status = _agent_status(
                record.get("last_seen"), record.get("status", "online")
            )
            risk = compute_agent_risk(
                status=status,
                health=health,
                alerts=alerts,
                capture=capture,
                flows=flows,
            )
            cleaned["risk"] = risk
            self._telemetry.setdefault(agent_id, []).append(cleaned)
            self._telemetry[agent_id] = self._telemetry[agent_id][-50:]
            record["last_seen"] = received_at
            record["last_telemetry_at"] = received_at
            record["last_telemetry"] = cleaned
            record["risk"] = risk
            self._agents[agent_id] = record
            if self._use_jsonl:
                self._append_jsonl(
                    {"type": "agent", "agent_id": agent_id, "record": record}
                )
                self._append_jsonl(
                    {"type": "telemetry", "agent_id": agent_id, "payload": cleaned}
                )
            else:
                self._upsert_agent(record)
                self._insert_telemetry_snapshots(agent_id, received_at, cleaned, risk)
            return {
                "ok": True,
                "agent_id": agent_id,
                "received_at": received_at,
                "risk": risk,
            }

    def _insert_telemetry_snapshots(
        self,
        agent_id: str,
        received_at: str,
        cleaned: dict[str, Any],
        risk: dict[str, Any],
    ) -> None:
        health = (
            cleaned.get("health") if isinstance(cleaned.get("health"), dict) else {}
        )
        alerts = (
            cleaned.get("alerts_summary")
            if isinstance(cleaned.get("alerts_summary"), dict)
            else {}
        )
        flows = (
            cleaned.get("flows_summary")
            if isinstance(cleaned.get("flows_summary"), dict)
            else {}
        )
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO agent_telemetry(agent_id, received_at, payload_json) VALUES (?, ?, ?)",
                (agent_id, received_at, _json_dumps(cleaned)),
            )
            conn.execute(
                """
                INSERT INTO agent_health_snapshots(
                    agent_id, received_at, cpu_percent, memory_percent,
                    disk_percent, payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    agent_id,
                    received_at,
                    health.get("cpu_percent"),
                    health.get("memory_percent"),
                    health.get("disk_percent"),
                    _json_dumps(health),
                ),
            )
            conn.execute(
                """
                INSERT INTO agent_alert_snapshots(
                    agent_id, received_at, total_alerts, critical_count,
                    high_count, medium_count, low_count, payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    agent_id,
                    received_at,
                    _count(alerts, "total_alerts", "total", "count"),
                    _count(alerts, "critical_count", "critical"),
                    _count(alerts, "high_count", "high"),
                    _count(alerts, "medium_count", "medium"),
                    _count(alerts, "low_count", "low"),
                    _json_dumps(alerts),
                ),
            )
            conn.execute(
                """
                INSERT INTO agent_flow_snapshots(agent_id, received_at, flow_count, payload_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    agent_id,
                    received_at,
                    _count(flows, "flow_count", "total_flows"),
                    _json_dumps(flows),
                ),
            )
            conn.execute(
                """
                INSERT INTO agent_risk_snapshots(agent_id, received_at, score, severity, payload_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    agent_id,
                    received_at,
                    int(risk.get("score") or 0),
                    str(risk.get("severity") or "low"),
                    _json_dumps(risk),
                ),
            )

    def list_agents(self) -> list[dict[str, Any]]:
        return [
            _agent_public(record)
            for record in sorted(
                self._agents.values(),
                key=lambda item: str(item.get("display_name") or item.get("agent_id")),
            )
        ]

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        record = self._agents.get(agent_id)
        return _agent_public(record) if record else None

    def get_telemetry(
        self,
        agent_id: str,
        limit: int = 20,
        range_name: str = "24h",
    ) -> list[dict[str, Any]]:
        if self._use_jsonl:
            return list(self._telemetry.get(agent_id, []))[-max(1, min(50, limit)) :]
        return self._history_payloads(
            "agent_telemetry", agent_id, "payload_json", range_name, limit
        )

    def history(
        self,
        agent_id: str,
        kind: str,
        range_name: str = "24h",
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        table_map = {
            "health": ("agent_health_snapshots", "payload_json"),
            "alerts": ("agent_alert_snapshots", "payload_json"),
            "flows": ("agent_flow_snapshots", "payload_json"),
            "risk": ("agent_risk_snapshots", "payload_json"),
            "heartbeats": ("agent_heartbeats", "payload_json"),
        }
        if kind not in table_map:
            return []
        if self._use_jsonl:
            return self.get_telemetry(agent_id, limit=limit, range_name=range_name)
        table, payload_column = table_map[kind]
        return self._history_payloads(
            table, agent_id, payload_column, range_name, limit
        )

    def cleanup_history(
        self,
        retention_days: int | str | None = None,
        *,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        try:
            days = int(
                retention_days
                if retention_days is not None
                else os.environ.get("NETBOT_AGENT_HISTORY_RETENTION_DAYS", "30")
            )
        except (TypeError, ValueError):
            days = 30
        days = max(1, min(3650, days))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        tables = [
            "agent_heartbeats",
            "agent_telemetry",
            "agent_health_snapshots",
            "agent_alert_snapshots",
            "agent_flow_snapshots",
            "agent_risk_snapshots",
        ]
        if self._use_jsonl:
            return {
                "dry_run": dry_run,
                "retention_days": days,
                "cutoff": cutoff,
                "deleted": {table: 0 for table in tables},
                "storage": "jsonl",
            }
        deleted: dict[str, int] = {}
        with self._lock:
            with self._connection() as conn:
                for table in tables:
                    count = conn.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE received_at < ?",
                        (cutoff,),
                    ).fetchone()[0]
                    deleted[table] = int(count or 0)
                    if not dry_run and count:
                        conn.execute(
                            f"DELETE FROM {table} WHERE received_at < ?",
                            (cutoff,),
                        )
        return {
            "dry_run": dry_run,
            "retention_days": days,
            "cutoff": cutoff,
            "deleted": deleted,
            "storage": "sqlite",
        }

    def delete_demo_agents(self) -> int:
        demo_ids = [
            agent_id
            for agent_id, agent in self._agents.items()
            if agent_id.startswith("demo-agent-")
            or "demo" in {str(item).lower() for item in agent.get("capabilities", [])}
        ]
        if not demo_ids:
            return 0
        with self._lock:
            for agent_id in demo_ids:
                self._agents.pop(agent_id, None)
                self._telemetry.pop(agent_id, None)
            if not self._use_jsonl:
                placeholders = ",".join("?" for _ in demo_ids)
                tables = [
                    "agent_heartbeats",
                    "agent_telemetry",
                    "agent_health_snapshots",
                    "agent_alert_snapshots",
                    "agent_flow_snapshots",
                    "agent_risk_snapshots",
                    "agents",
                ]
                with self._connection() as conn:
                    for table in tables:
                        conn.execute(
                            f"DELETE FROM {table} WHERE agent_id IN ({placeholders})",
                            demo_ids,
                        )
        return len(demo_ids)

    def set_agent_last_seen(
        self,
        agent_id: str,
        last_seen: str,
        *,
        status: str = "online",
    ) -> None:
        with self._lock:
            if agent_id not in self._agents:
                raise KeyError(agent_id)
            record = dict(self._agents[agent_id])
            record["last_seen"] = last_seen
            record["status"] = status
            self._agents[agent_id] = record
            if not self._use_jsonl:
                self._upsert_agent(record)

    def _history_payloads(
        self,
        table: str,
        agent_id: str,
        payload_column: str,
        range_name: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(_MAX_HISTORY_LIMIT, int(limit or 200)))
        with self._connection() as conn:
            rows = conn.execute(
                f"""
                SELECT received_at, {payload_column} AS payload
                FROM {table}
                WHERE agent_id = ? AND received_at >= ?
                ORDER BY received_at DESC
                LIMIT ?
                """,
                (agent_id, _range_start(range_name), limit),
            ).fetchall()
        items = []
        for row in reversed(rows):
            payload = _json_loads(row["payload"], {})
            if isinstance(payload, dict):
                payload.setdefault("received_at", row["received_at"])
            items.append(payload)
        return items

    def overview(self) -> dict[str, Any]:
        agents = self.list_agents()
        online = [agent for agent in agents if agent.get("status") == "online"]
        offline = [agent for agent in agents if agent.get("status") == "offline"]
        high_risk = [
            agent
            for agent in agents
            if (agent.get("risk") or {}).get("severity") in {"high", "critical"}
        ]
        total_alerts = 0
        critical_alerts = 0
        cpu_values: list[float] = []
        memory_values: list[float] = []
        disk_values: list[float] = []
        for agent in agents:
            telemetry = agent.get("last_telemetry") or {}
            alerts = telemetry.get("alerts_summary") or {}
            health = telemetry.get("health") or {}
            total_alerts += _count(alerts, "total_alerts", "total", "count")
            critical_alerts += _count(alerts, "critical_count", "critical")
            for key, bucket in (
                ("cpu_percent", cpu_values),
                ("memory_percent", memory_values),
                ("disk_percent", disk_values),
            ):
                try:
                    bucket.append(float(health.get(key)))
                except (TypeError, ValueError):
                    pass
        top_risky = sorted(
            agents,
            key=lambda agent: int((agent.get("risk") or {}).get("score") or 0),
            reverse=True,
        )[:5]
        return {
            "total_agents": len(agents),
            "online_agents": len(online),
            "offline_agents": len(offline),
            "high_risk_agents": len(high_risk),
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "average_cpu_percent": (
                round(sum(cpu_values) / len(cpu_values), 1) if cpu_values else 0
            ),
            "average_memory_percent": (
                round(sum(memory_values) / len(memory_values), 1)
                if memory_values
                else 0
            ),
            "average_disk_percent": (
                round(sum(disk_values) / len(disk_values), 1) if disk_values else 0
            ),
            "demo_data": any(
                "demo" in {str(item).lower() for item in agent.get("capabilities", [])}
                for agent in agents
            ),
            "top_risky_agents": top_risky,
        }

    def alerts_summary(self) -> dict[str, Any]:
        agents = self.list_agents()
        summary = {
            "total_alerts": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
        }
        for agent in agents:
            alerts = (agent.get("last_telemetry") or {}).get("alerts_summary") or {}
            summary["total_alerts"] += _count(alerts, "total_alerts", "total", "count")
            summary["critical_count"] += _count(alerts, "critical_count", "critical")
            summary["high_count"] += _count(alerts, "high_count", "high")
            summary["medium_count"] += _count(alerts, "medium_count", "medium")
            summary["low_count"] += _count(alerts, "low_count", "low")
        return summary

    def risk_summary(self) -> dict[str, Any]:
        agents = self.list_agents()
        buckets = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for agent in agents:
            severity = str((agent.get("risk") or {}).get("severity") or "low")
            buckets[severity if severity in buckets else "low"] += 1
        return {
            "buckets": buckets,
            "top_risky_agents": self.overview()["top_risky_agents"],
        }

    def fleet_summary_report(self) -> dict[str, Any]:
        agents = self.list_agents()
        overview = self.overview()
        alerts = self.alerts_summary()
        risk = self.risk_summary()
        health_summary = {
            "average_cpu_percent": overview["average_cpu_percent"],
            "average_memory_percent": overview["average_memory_percent"],
            "average_disk_percent": overview["average_disk_percent"],
        }
        rows = []
        for agent in agents:
            telemetry = agent.get("last_telemetry") or {}
            alert_summary = telemetry.get("alerts_summary") or {}
            health = telemetry.get("health") or {}
            capture = telemetry.get("capture") or {}
            rows.append(
                {
                    "agent_id": agent.get("agent_id"),
                    "hostname": agent.get("hostname"),
                    "display_name": agent.get("display_name"),
                    "status": agent.get("status"),
                    "os": agent.get("os") or agent.get("platform"),
                    "last_seen": agent.get("last_seen"),
                    "cpu_percent": health.get("cpu_percent"),
                    "memory_percent": health.get("memory_percent"),
                    "disk_percent": health.get("disk_percent"),
                    "capture_running": bool(
                        capture.get("capture_running") or capture.get("running")
                    ),
                    "capture_mode": capture.get("capture_mode")
                    or capture.get("mode")
                    or "metadata",
                    "total_alerts": _count(alert_summary, "total_alerts", "total"),
                    "critical_alerts": _count(
                        alert_summary, "critical_count", "critical"
                    ),
                    "risk_score": (agent.get("risk") or {}).get("score", 0),
                    "risk_severity": (agent.get("risk") or {}).get("severity", "low"),
                }
            )
        recommendations = []
        if overview["offline_agents"]:
            recommendations.append("Review offline agents and confirm service health.")
        if overview["critical_alerts"]:
            recommendations.append("Prioritize agents with critical alert activity.")
        if overview["high_risk_agents"]:
            recommendations.append(
                "Inspect high-risk servers and recent telemetry trends."
            )
        if not recommendations:
            recommendations.append(
                "Fleet is currently stable; continue routine monitoring."
            )
        return _redact(
            {
                "generated_at": _now(),
                "total_agents": overview["total_agents"],
                "online_agents": overview["online_agents"],
                "offline_agents": overview["offline_agents"],
                "high_risk_agents": overview["high_risk_agents"],
                "critical_alerts": overview["critical_alerts"],
                "top_risky_agents": overview["top_risky_agents"],
                "agents": rows,
                "risk_distribution": risk["buckets"],
                "alert_distribution": alerts,
                "health_summary": health_summary,
                "recommended_actions": recommendations,
                "demo_data": overview["demo_data"],
            }
        )


def cleanup_agent_history(
    retention_days: int | str | None = None,
    *,
    storage_path: str | Path | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    registry = AgentRegistry(storage_path)
    return registry.cleanup_history(retention_days, dry_run=dry_run)
