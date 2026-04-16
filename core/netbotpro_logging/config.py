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
    "capture_id": "ALTER TABLE packets ADD COLUMN capture_id TEXT",
    "remote_ip": "ALTER TABLE packets ADD COLUMN remote_ip TEXT",
    "app_protocol": "ALTER TABLE packets ADD COLUMN app_protocol TEXT",
    "app_category": "ALTER TABLE packets ADD COLUMN app_category TEXT",
    "app_confidence": "ALTER TABLE packets ADD COLUMN app_confidence TEXT",
    "protocol_basis": "ALTER TABLE packets ADD COLUMN protocol_basis TEXT",
    "protocol_notes": "ALTER TABLE packets ADD COLUMN protocol_notes TEXT",
    "protocol_handshake": "ALTER TABLE packets ADD COLUMN protocol_handshake TEXT",
    "protocol_unusual_port": "ALTER TABLE packets ADD COLUMN protocol_unusual_port INTEGER",
    "l7": "ALTER TABLE packets ADD COLUMN l7 TEXT",
    "dns_qname": "ALTER TABLE packets ADD COLUMN dns_qname TEXT",
    "dns_qtype": "ALTER TABLE packets ADD COLUMN dns_qtype INTEGER",
    "dns_rcode": "ALTER TABLE packets ADD COLUMN dns_rcode INTEGER",
    "http_method": "ALTER TABLE packets ADD COLUMN http_method TEXT",
    "http_status": "ALTER TABLE packets ADD COLUMN http_status INTEGER",
    "http_reason": "ALTER TABLE packets ADD COLUMN http_reason TEXT",
    "http_host": "ALTER TABLE packets ADD COLUMN http_host TEXT",
    "http_path": "ALTER TABLE packets ADD COLUMN http_path TEXT",
    "http_user_agent": "ALTER TABLE packets ADD COLUMN http_user_agent TEXT",
    "http_content_type": "ALTER TABLE packets ADD COLUMN http_content_type TEXT",
    "sni": "ALTER TABLE packets ADD COLUMN sni TEXT",
    "tls_version": "ALTER TABLE packets ADD COLUMN tls_version TEXT",
    "tls_alpn": "ALTER TABLE packets ADD COLUMN tls_alpn TEXT",
    "ja3": "ALTER TABLE packets ADD COLUMN ja3 TEXT",
    "ja3_str": "ALTER TABLE packets ADD COLUMN ja3_str TEXT",
    "ja4": "ALTER TABLE packets ADD COLUMN ja4 TEXT",
    "payload_len": "ALTER TABLE packets ADD COLUMN payload_len INTEGER",
    "payload_hex": "ALTER TABLE packets ADD COLUMN payload_hex TEXT",
    "payload_ascii": "ALTER TABLE packets ADD COLUMN payload_ascii TEXT",
    "payload_binary_like": "ALTER TABLE packets ADD COLUMN payload_binary_like INTEGER",
    "payload_entropy": "ALTER TABLE packets ADD COLUMN payload_entropy REAL",
    "payload_printable_ratio": "ALTER TABLE packets ADD COLUMN payload_printable_ratio REAL",
    "pid": "ALTER TABLE packets ADD COLUMN pid INTEGER",
    "process_name": "ALTER TABLE packets ADD COLUMN process_name TEXT",
    "parent_pid": "ALTER TABLE packets ADD COLUMN parent_pid INTEGER",
    "parent_process_name": "ALTER TABLE packets ADD COLUMN parent_process_name TEXT",
    "executable_path": "ALTER TABLE packets ADD COLUMN executable_path TEXT",
    "attribution_confidence": "ALTER TABLE packets ADD COLUMN attribution_confidence TEXT",
    "attribution_reason_unavailable": "ALTER TABLE packets ADD COLUMN attribution_reason_unavailable TEXT",
    "attribution_source": "ALTER TABLE packets ADD COLUMN attribution_source TEXT",
}

_ALERT_SCHEMA_UPDATES = {
    "severity": "ALTER TABLE alerts ADD COLUMN severity TEXT",
    "engine": "ALTER TABLE alerts ADD COLUMN engine TEXT",
    "score_raw": "ALTER TABLE alerts ADD COLUMN score_raw REAL",
    "incident_id": "ALTER TABLE alerts ADD COLUMN incident_id TEXT",
    "incident_count": "ALTER TABLE alerts ADD COLUMN incident_count INTEGER",
    "incident_score": "ALTER TABLE alerts ADD COLUMN incident_score REAL",
    "packet_id": "ALTER TABLE alerts ADD COLUMN packet_id TEXT",
    "direction": "ALTER TABLE alerts ADD COLUMN direction TEXT",
    "sport": "ALTER TABLE alerts ADD COLUMN sport INTEGER",
    "dport": "ALTER TABLE alerts ADD COLUMN dport INTEGER",
    "remote_ip": "ALTER TABLE alerts ADD COLUMN remote_ip TEXT",
    "app_protocol": "ALTER TABLE alerts ADD COLUMN app_protocol TEXT",
    "app_category": "ALTER TABLE alerts ADD COLUMN app_category TEXT",
    "app_confidence": "ALTER TABLE alerts ADD COLUMN app_confidence TEXT",
    "protocol_basis": "ALTER TABLE alerts ADD COLUMN protocol_basis TEXT",
    "protocol_notes": "ALTER TABLE alerts ADD COLUMN protocol_notes TEXT",
    "protocol_handshake": "ALTER TABLE alerts ADD COLUMN protocol_handshake TEXT",
    "protocol_unusual_port": "ALTER TABLE alerts ADD COLUMN protocol_unusual_port INTEGER",
    "dns_qname": "ALTER TABLE alerts ADD COLUMN dns_qname TEXT",
    "dns_qtype": "ALTER TABLE alerts ADD COLUMN dns_qtype INTEGER",
    "dns_rcode": "ALTER TABLE alerts ADD COLUMN dns_rcode INTEGER",
    "http_method": "ALTER TABLE alerts ADD COLUMN http_method TEXT",
    "http_host": "ALTER TABLE alerts ADD COLUMN http_host TEXT",
    "http_path": "ALTER TABLE alerts ADD COLUMN http_path TEXT",
    "http_status": "ALTER TABLE alerts ADD COLUMN http_status INTEGER",
    "http_reason": "ALTER TABLE alerts ADD COLUMN http_reason TEXT",
    "http_user_agent": "ALTER TABLE alerts ADD COLUMN http_user_agent TEXT",
    "http_content_type": "ALTER TABLE alerts ADD COLUMN http_content_type TEXT",
    "sni": "ALTER TABLE alerts ADD COLUMN sni TEXT",
    "tls_version": "ALTER TABLE alerts ADD COLUMN tls_version TEXT",
    "tls_alpn": "ALTER TABLE alerts ADD COLUMN tls_alpn TEXT",
    "ja3": "ALTER TABLE alerts ADD COLUMN ja3 TEXT",
    "ja3_str": "ALTER TABLE alerts ADD COLUMN ja3_str TEXT",
    "ja4": "ALTER TABLE alerts ADD COLUMN ja4 TEXT",
    "payload_len": "ALTER TABLE alerts ADD COLUMN payload_len INTEGER",
    "payload_hex": "ALTER TABLE alerts ADD COLUMN payload_hex TEXT",
    "payload_ascii": "ALTER TABLE alerts ADD COLUMN payload_ascii TEXT",
    "payload_binary_like": "ALTER TABLE alerts ADD COLUMN payload_binary_like INTEGER",
    "payload_entropy": "ALTER TABLE alerts ADD COLUMN payload_entropy REAL",
    "payload_printable_ratio": "ALTER TABLE alerts ADD COLUMN payload_printable_ratio REAL",
    "pid": "ALTER TABLE alerts ADD COLUMN pid INTEGER",
    "process_name": "ALTER TABLE alerts ADD COLUMN process_name TEXT",
    "parent_pid": "ALTER TABLE alerts ADD COLUMN parent_pid INTEGER",
    "parent_process_name": "ALTER TABLE alerts ADD COLUMN parent_process_name TEXT",
    "executable_path": "ALTER TABLE alerts ADD COLUMN executable_path TEXT",
    "attribution_confidence": "ALTER TABLE alerts ADD COLUMN attribution_confidence TEXT",
    "attribution_reason_unavailable": "ALTER TABLE alerts ADD COLUMN attribution_reason_unavailable TEXT",
    "attribution_source": "ALTER TABLE alerts ADD COLUMN attribution_source TEXT",
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
                capture_id TEXT,
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
                protocol_basis TEXT,
                protocol_notes TEXT,
                protocol_handshake TEXT,
                protocol_unusual_port INTEGER,
                l7 TEXT,
                dns_qname TEXT,
                dns_qtype INTEGER,
                dns_rcode INTEGER,
                http_method TEXT,
                http_status INTEGER,
                http_reason TEXT,
                http_host TEXT,
                http_path TEXT,
                http_user_agent TEXT,
                http_content_type TEXT,
                sni TEXT,
                tls_version TEXT,
                tls_alpn TEXT,
                ja3 TEXT,
                ja3_str TEXT,
                ja4 TEXT,
                payload_len INTEGER,
                payload_hex TEXT,
                payload_ascii TEXT,
                payload_binary_like INTEGER,
                payload_entropy REAL,
                payload_printable_ratio REAL,
                pid INTEGER,
                process_name TEXT,
                parent_pid INTEGER,
                parent_process_name TEXT,
                executable_path TEXT,
                attribution_confidence TEXT,
                attribution_reason_unavailable TEXT,
                attribution_source TEXT
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
                direction TEXT,
                sport INTEGER,
                dport INTEGER,
                remote_ip TEXT,
                app_protocol TEXT,
                app_category TEXT,
                app_confidence TEXT,
                protocol_basis TEXT,
                protocol_notes TEXT,
                protocol_handshake TEXT,
                protocol_unusual_port INTEGER,
                dns_qname TEXT,
                dns_qtype INTEGER,
                dns_rcode INTEGER,
                http_method TEXT,
                http_host TEXT,
                http_path TEXT,
                http_status INTEGER,
                http_reason TEXT,
                http_user_agent TEXT,
                http_content_type TEXT,
                sni TEXT,
                tls_version TEXT,
                tls_alpn TEXT,
                ja3 TEXT,
                ja3_str TEXT,
                ja4 TEXT,
                payload_len INTEGER,
                payload_hex TEXT,
                payload_ascii TEXT,
                payload_binary_like INTEGER,
                payload_entropy REAL,
                payload_printable_ratio REAL,
                pid INTEGER,
                process_name TEXT,
                parent_pid INTEGER,
                parent_process_name TEXT,
                executable_path TEXT,
                attribution_confidence TEXT,
                attribution_reason_unavailable TEXT,
                attribution_source TEXT
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
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_packets_capture_id ON packets(capture_id)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_packets_process_name ON packets(process_name)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_packets_pid ON packets(pid)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_dst ON alerts(dst)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_proto ON alerts(proto)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_app_protocol ON alerts(app_protocol)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(score)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_remote_ip ON alerts(remote_ip)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_packet_id ON alerts(packet_id)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_process_name ON alerts(process_name)")
        _CONN.execute("CREATE INDEX IF NOT EXISTS idx_alerts_pid ON alerts(pid)")
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
