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


def _insert_packets_no_commit(conn, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    conn.executemany(
        """
        INSERT INTO packets (
            ts, src, dst, proto, sport, dport, length,
            country, org, summary, is_alert, remote_ip,
            app_protocol, app_category, app_confidence, l7,
            dns_qname, http_host, http_path, sni, tls_version
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                row.get("ts"),
                row.get("src"),
                row.get("dst"),
                row.get("proto"),
                row.get("sport"),
                row.get("dport"),
                row.get("length"),
                row.get("country"),
                row.get("org"),
                row.get("summary"),
                1 if row.get("is_alert") else 0,
                row.get("remote_ip"),
                row.get("app_protocol"),
                row.get("app_category"),
                row.get("app_confidence"),
                row.get("l7"),
                row.get("dns_qname"),
                row.get("http_host"),
                row.get("http_path"),
                row.get("sni"),
                row.get("tls_version"),
            )
            for row in rows
        ],
    )


def _insert_alerts_no_commit(conn, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    conn.executemany(
        """
        INSERT INTO alerts (
            ts, src, dst, proto, attack_type, score, detail,
            severity, engine, score_raw, incident_id,
            incident_count, incident_score, packet_id, remote_ip,
            app_protocol, app_category, app_confidence, dns_qname,
            http_host, http_path, sni
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                row.get("ts"),
                row.get("src"),
                row.get("dst"),
                row.get("proto"),
                row.get("attack_type"),
                row.get("score"),
                row.get("detail"),
                row.get("severity"),
                row.get("engine"),
                row.get("score_raw"),
                row.get("incident_id"),
                row.get("incident_count"),
                row.get("incident_score"),
                row.get("packet_id"),
                row.get("remote_ip"),
                row.get("app_protocol"),
                row.get("app_category"),
                row.get("app_confidence"),
                row.get("dns_qname"),
                row.get("http_host"),
                row.get("http_path"),
                row.get("sni"),
            )
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
