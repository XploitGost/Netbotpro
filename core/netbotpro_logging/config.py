from __future__ import annotations

import os
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get("NETBOT_DATA_DIR", str(BASE_DIR)))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = os.environ.get("NETBOT_DB_PATH", str(DATA_DIR / "netbot.db"))
SQLITE_BUSY_TIMEOUT_MS = 5_000

try:
    from fpdf import FPDF  # type: ignore
except Exception:
    FPDF = None  # type: ignore

_env_log_dir = os.environ.get("NETBOT_LOG_DIR")
_local_log_dir = DATA_DIR / "logs"
_user_log_dir = Path(os.path.expanduser("~")) / ".netbotpro" / "logs"

LOG_DIR = Path(_env_log_dir or _local_log_dir)
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    test_file = LOG_DIR / ".write_test"
    test_file.write_text("ok", encoding="utf-8")
    test_file.unlink(missing_ok=True)
except Exception:
    LOG_DIR = Path(_env_log_dir or _user_log_dir)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

PERSIST_LOGS = False
_CONN: sqlite3.Connection | None = None

_PACKET_SCHEMA_UPDATES = {
    "remote_ip": "ALTER TABLE packets ADD COLUMN remote_ip TEXT",
    "app_protocol": "ALTER TABLE packets ADD COLUMN app_protocol TEXT",
    "app_category": "ALTER TABLE packets ADD COLUMN app_category TEXT",
    "app_confidence": "ALTER TABLE packets ADD COLUMN app_confidence TEXT",
    "l7": "ALTER TABLE packets ADD COLUMN l7 TEXT",
    "dns_qname": "ALTER TABLE packets ADD COLUMN dns_qname TEXT",
    "http_host": "ALTER TABLE packets ADD COLUMN http_host TEXT",
    "http_path": "ALTER TABLE packets ADD COLUMN http_path TEXT",
    "sni": "ALTER TABLE packets ADD COLUMN sni TEXT",
    "tls_version": "ALTER TABLE packets ADD COLUMN tls_version TEXT",
}

_ALERT_SCHEMA_UPDATES = {
    "severity": "ALTER TABLE alerts ADD COLUMN severity TEXT",
    "engine": "ALTER TABLE alerts ADD COLUMN engine TEXT",
    "score_raw": "ALTER TABLE alerts ADD COLUMN score_raw REAL",
    "incident_id": "ALTER TABLE alerts ADD COLUMN incident_id TEXT",
    "incident_count": "ALTER TABLE alerts ADD COLUMN incident_count INTEGER",
    "incident_score": "ALTER TABLE alerts ADD COLUMN incident_score REAL",
    "packet_id": "ALTER TABLE alerts ADD COLUMN packet_id TEXT",
    "remote_ip": "ALTER TABLE alerts ADD COLUMN remote_ip TEXT",
    "app_protocol": "ALTER TABLE alerts ADD COLUMN app_protocol TEXT",
    "app_category": "ALTER TABLE alerts ADD COLUMN app_category TEXT",
    "app_confidence": "ALTER TABLE alerts ADD COLUMN app_confidence TEXT",
    "dns_qname": "ALTER TABLE alerts ADD COLUMN dns_qname TEXT",
    "http_host": "ALTER TABLE alerts ADD COLUMN http_host TEXT",
    "http_path": "ALTER TABLE alerts ADD COLUMN http_path TEXT",
    "sni": "ALTER TABLE alerts ADD COLUMN sni TEXT",
}


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, statement: str) -> None:
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column in existing:
        return
    conn.execute(statement)


def _configure_connection(conn: sqlite3.Connection) -> None:
    conn.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")


def set_persist(enabled: bool) -> None:
    global PERSIST_LOGS, _CONN
    PERSIST_LOGS = bool(enabled)
    if not PERSIST_LOGS and _CONN is not None:
        try:
            _CONN.close()
        except Exception:
            pass
        _CONN = None


def is_persist_enabled() -> bool:
    return bool(PERSIST_LOGS)


def get_conn() -> sqlite3.Connection | None:
    global _CONN
    if not PERSIST_LOGS:
        return None
    if _CONN is None:
        _CONN = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=SQLITE_BUSY_TIMEOUT_MS / 1000.0)
        _configure_connection(_CONN)
        _CONN.execute(
            """
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                src TEXT,
                dst TEXT,
                proto TEXT,
                sport INTEGER,
                dport INTEGER,
                length INTEGER,
                country TEXT,
                org TEXT,
                summary TEXT,
                is_alert INTEGER DEFAULT 0,
                remote_ip TEXT,
                app_protocol TEXT,
                app_category TEXT,
                app_confidence TEXT,
                l7 TEXT,
                dns_qname TEXT,
                http_host TEXT,
                http_path TEXT,
                sni TEXT,
                tls_version TEXT
            )
            """
        )
        _CONN.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                src TEXT,
                dst TEXT,
                proto TEXT,
                attack_type TEXT,
                score REAL,
                detail TEXT,
                severity TEXT,
                engine TEXT,
                score_raw REAL,
                incident_id TEXT,
                incident_count INTEGER,
                incident_score REAL,
                packet_id TEXT,
                remote_ip TEXT,
                app_protocol TEXT,
                app_category TEXT,
                app_confidence TEXT,
                dns_qname TEXT,
                http_host TEXT,
                http_path TEXT,
                sni TEXT
            )
            """
        )
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_packets_proto ON packets(proto)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_packets_app_protocol ON packets(app_protocol)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_packets_remote_ip ON packets(remote_ip)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_packets_is_alert ON packets(is_alert)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_dst ON alerts(dst)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_proto ON alerts(proto)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_app_protocol ON alerts(app_protocol)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(score)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_remote_ip ON alerts(remote_ip)")
        for column, statement in _PACKET_SCHEMA_UPDATES.items():
            _ensure_column(_CONN, "packets", column, statement)
        for column, statement in _ALERT_SCHEMA_UPDATES.items():
            _ensure_column(_CONN, "alerts", column, statement)
        _CONN.commit()
    return _CONN


def init_storage() -> None:
    if not PERSIST_LOGS:
        return
    _ = get_conn()
