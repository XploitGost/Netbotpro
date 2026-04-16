from __future__ import annotations

import logging
import sqlite3
import threading
import time
from typing import Any

from .config import get_conn, is_persist_enabled

_DB_LOCK = threading.Lock()
logger = logging.getLogger(__name__)
_LOCK_RETRY_DELAYS_SEC = (0.02, 0.05, 0.1)

_PACKET_COLUMNS = (
    "capture_id",
    "ts",
    "src",
    "dst",
    "proto",
    "sport",
    "dport",
    "length",
    "country",
    "org",
    "summary",
    "is_alert",
    "remote_ip",
    "app_protocol",
    "app_category",
    "app_confidence",
    "protocol_basis",
    "protocol_notes",
    "protocol_handshake",
    "protocol_unusual_port",
    "l7",
    "dns_qname",
    "dns_qtype",
    "dns_rcode",
    "http_method",
    "http_status",
    "http_reason",
    "http_host",
    "http_path",
    "http_user_agent",
    "http_content_type",
    "sni",
    "tls_version",
    "tls_alpn",
    "ja3",
    "ja3_str",
    "ja4",
    "payload_len",
    "payload_hex",
    "payload_ascii",
    "payload_binary_like",
    "payload_entropy",
    "payload_printable_ratio",
    "pid",
    "process_name",
    "parent_pid",
    "parent_process_name",
    "executable_path",
    "attribution_confidence",
    "attribution_reason_unavailable",
    "attribution_source",
)

_ALERT_COLUMNS = (
    "ts",
    "src",
    "dst",
    "proto",
    "sport",
    "dport",
    "direction",
    "attack_type",
    "score",
    "detail",
    "severity",
    "engine",
    "score_raw",
    "incident_id",
    "incident_count",
    "incident_score",
    "packet_id",
    "remote_ip",
    "app_protocol",
    "app_category",
    "app_confidence",
    "protocol_basis",
    "protocol_notes",
    "protocol_handshake",
    "protocol_unusual_port",
    "dns_qname",
    "dns_qtype",
    "dns_rcode",
    "http_method",
    "http_host",
    "http_path",
    "http_status",
    "http_reason",
    "http_user_agent",
    "http_content_type",
    "sni",
    "tls_version",
    "tls_alpn",
    "ja3",
    "ja3_str",
    "ja4",
    "payload_len",
    "payload_hex",
    "payload_ascii",
    "payload_binary_like",
    "payload_entropy",
    "payload_printable_ratio",
    "pid",
    "process_name",
    "parent_pid",
    "parent_process_name",
    "executable_path",
    "attribution_confidence",
    "attribution_reason_unavailable",
    "attribution_source",
)


def _insert_packets_no_commit(conn, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    conn.executemany(
        f"INSERT INTO packets ({', '.join(_PACKET_COLUMNS)}) VALUES ({', '.join(['?'] * len(_PACKET_COLUMNS))})",
        [
            tuple((1 if column == "is_alert" and row.get(column) else 0) if column == "is_alert" else row.get(column) for column in _PACKET_COLUMNS)
            for row in rows
        ],
    )


def _insert_alerts_no_commit(conn, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    conn.executemany(
        f"INSERT INTO alerts ({', '.join(_ALERT_COLUMNS)}) VALUES ({', '.join(['?'] * len(_ALERT_COLUMNS))})",
        [
            tuple(row.get(column) for column in _ALERT_COLUMNS)
            for row in rows
        ],
    )


def _is_retryable_sqlite_error(exc: sqlite3.Error) -> bool:
    text = str(exc).lower()
    return "locked" in text or "busy" in text


def insert_batch(packet_rows: list[dict[str, Any]], alert_rows: list[dict[str, Any]]) -> dict[str, int]:
    if not is_persist_enabled():
        return {"retries": 0}
    conn = get_conn()
    if conn is None:
        return {"retries": 0}
    with _DB_LOCK:
        retries = 0
        for attempt, delay in enumerate((0.0, *_LOCK_RETRY_DELAYS_SEC)):
            try:
                _insert_packets_no_commit(conn, packet_rows)
                _insert_alerts_no_commit(conn, alert_rows)
                conn.commit()
                return {"retries": retries}
            except sqlite3.Error as exc:
                conn.rollback()
                if attempt >= len(_LOCK_RETRY_DELAYS_SEC) or not _is_retryable_sqlite_error(exc):
                    raise
                retries += 1
                logger.warning("sqlite_write_retry retries=%s delay_ms=%.0f error=%s", retries, delay * 1000.0, exc)
                time.sleep(delay)
        return {"retries": retries}


def insert_packet(row: dict[str, Any]) -> None:
    if not row:
        return
    insert_batch([row], [])


def insert_alert(row: dict[str, Any]) -> None:
    if not row:
        return
    insert_batch([], [row])


def cleanup_retention(retention_minutes: int) -> None:
    if not is_persist_enabled():
        return
    try:
        minutes = int(retention_minutes)
    except Exception:
        return
    if minutes <= 0:
        return
    conn = get_conn()
    if conn is None:
        return
    try:
        with _DB_LOCK:
            conn.execute("ALTER TABLE packets ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP")
            conn.commit()
    except Exception:
        pass
    try:
        with _DB_LOCK:
            conn.execute("ALTER TABLE alerts ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP")
            conn.commit()
    except Exception:
        pass
    try:
        with _DB_LOCK:
            conn.execute("DELETE FROM packets WHERE created_at IS NOT NULL AND datetime(created_at) < datetime('now', ?)", (f"-{minutes} minutes",))
            conn.execute("DELETE FROM alerts WHERE created_at IS NOT NULL AND datetime(created_at) < datetime('now', ?)", (f"-{minutes} minutes",))
            conn.commit()
    except Exception:
        pass
