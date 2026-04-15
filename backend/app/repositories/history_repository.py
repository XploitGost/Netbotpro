from __future__ import annotations

import asyncio
import aiosqlite
from dataclasses import dataclass
import sqlite3
from typing import Any, Callable, Protocol

from backend.app.bootstrap import ensure_project_root_on_path

ensure_project_root_on_path()

from core.netbotpro_sniffer_core.ip_utils import is_local_ip, is_public_ip, is_remote_ip, preferred_remote_ip
from log_manager import DB_PATH  # noqa: E402


class HistoryRepositoryError(RuntimeError):
    pass


def _coerce_positive_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        num = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, num))


def _is_local_ip(value: str | None) -> bool:
    return is_local_ip(value)


def _is_public_ip(value: str | None) -> bool:
    return is_public_ip(value)


def _is_remote_traffic(row: dict[str, Any]) -> bool:
    src = str(row.get("src") or "").strip()
    dst = str(row.get("dst") or "").strip()
    remote_ip = str(row.get("remote_ip") or "").strip()
    candidates = [candidate for candidate in (remote_ip, src, dst) if candidate]
    return any(is_remote_ip(candidate) for candidate in candidates)


def _preferred_remote_ip(
    row: dict[str, Any] | tuple[Any, ...],
    *,
    remote_index: int | None = None,
    src_index: int | None = None,
    dst_index: int | None = None,
) -> str | None:
    if isinstance(row, dict):
        remote_ip = str(row.get("remote_ip") or "").strip()
        src = str(row.get("src") or "").strip()
        dst = str(row.get("dst") or "").strip()
    else:
        remote_ip = str(row[remote_index] or "").strip() if remote_index is not None else ""
        src = str(row[src_index] or "").strip() if src_index is not None else ""
        dst = str(row[dst_index] or "").strip() if dst_index is not None else ""

    return preferred_remote_ip(remote_ip, dst, src)


def _sqlite_is_remote_flow(src: Any, dst: Any, remote_ip: Any) -> int:
    return 1 if _is_remote_traffic({"src": src, "dst": dst, "remote_ip": remote_ip}) else 0


def _sqlite_remote_clause() -> str:
    return "netbot_is_remote_flow(src, dst, remote_ip) = 1"


@dataclass(frozen=True)
class PacketListQuery:
    src: str = ""
    dst: str = ""
    proto: str = ""
    text: str = ""
    only_alerts: bool = False
    only_remote: bool = False
    limit: int = 50
    offset: int = 0

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "PacketListQuery":
        return cls(
            src=str(raw.get("src") or "").strip(),
            dst=str(raw.get("dst") or "").strip(),
            proto=str(raw.get("proto") or "").strip(),
            text=str(raw.get("text") or "").strip(),
            only_alerts=str(raw.get("only_alerts") or "").strip().lower() in {"1", "true", "yes"},
            only_remote=str(raw.get("only_remote") or "").strip().lower() in {"1", "true", "yes"},
            limit=_coerce_positive_int(raw.get("limit"), default=50, minimum=1, maximum=200),
            offset=_coerce_positive_int(raw.get("offset"), default=0, minimum=0, maximum=100000),
        )


@dataclass(frozen=True)
class AlertListQuery:
    src: str = ""
    dst: str = ""
    attack: str = ""
    proto: str = ""
    text: str = ""
    min_score: str = ""
    only_remote: bool = False
    limit: int = 50
    offset: int = 0

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "AlertListQuery":
        return cls(
            src=str(raw.get("src") or "").strip(),
            dst=str(raw.get("dst") or "").strip(),
            attack=str(raw.get("attack") or "").strip(),
            proto=str(raw.get("proto") or "").strip(),
            text=str(raw.get("text") or "").strip(),
            min_score=str(raw.get("min_score") or "").strip(),
            only_remote=str(raw.get("only_remote") or "").strip().lower() in {"1", "true", "yes"},
            limit=_coerce_positive_int(raw.get("limit"), default=50, minimum=1, maximum=200),
            offset=_coerce_positive_int(raw.get("offset"), default=0, minimum=0, maximum=100000),
        )


class HistoryRepository(Protocol):
    def list_packets(self, query: PacketListQuery) -> dict[str, Any]:
        ...

    def list_alerts(self, query: AlertListQuery) -> dict[str, Any]:
        ...

    def get_packet_detail(self, packet_id: str) -> dict[str, Any] | None:
        ...

    def get_alert_detail(self, alert_id: str) -> dict[str, Any] | None:
        ...

    async def alist_packets(self, query: PacketListQuery) -> dict[str, Any]:
        ...

    async def alist_alerts(self, query: AlertListQuery) -> dict[str, Any]:
        ...

    async def aget_packet_detail(self, packet_id: str) -> dict[str, Any] | None:
        ...

    async def aget_alert_detail(self, alert_id: str) -> dict[str, Any] | None:
        ...


class BaseHistoryRepository:
    async def alist_packets(self, query: PacketListQuery) -> dict[str, Any]:
        return await asyncio.to_thread(self.list_packets, query)

    async def alist_alerts(self, query: AlertListQuery) -> dict[str, Any]:
        return await asyncio.to_thread(self.list_alerts, query)

    async def aget_packet_detail(self, packet_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self.get_packet_detail, packet_id)

    async def aget_alert_detail(self, alert_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self.get_alert_detail, alert_id)


class MemoryHistoryRepository(BaseHistoryRepository):
    def __init__(self, sniffer_service: Any) -> None:
        self._sniffer_service = sniffer_service

    def list_packets(self, query: PacketListQuery) -> dict[str, Any]:
        rows = list(self._sniffer_service.recent_packets())

        def match(row: dict[str, Any]) -> bool:
            if query.src and query.src.lower() not in str(row.get("src") or "").lower():
                return False
            if query.dst and query.dst.lower() not in str(row.get("dst") or "").lower():
                return False
            if query.proto and query.proto.lower() not in str(row.get("proto") or "").lower():
                return False
            if query.text:
                hay = " ".join(
                    [
                        str(row.get("summary") or ""),
                        str(row.get("org") or ""),
                        str(row.get("country") or row.get("country_code") or ""),
                        str(row.get("remote_ip") or ""),
                        str(row.get("app_protocol") or ""),
                        str(row.get("l7") or ""),
                        str(row.get("dns_qname") or ""),
                        str(row.get("http_host") or ""),
                        str(row.get("http_path") or ""),
                        str(row.get("sni") or ""),
                    ]
                ).lower()
                if query.text.lower() not in hay:
                    return False
            if query.only_alerts and not bool(row.get("is_alert")):
                return False
            if query.only_remote and not _is_remote_traffic(row):
                return False
            return True

        filtered = [dict(row) for row in rows if match(row)]
        total = len(filtered)
        items = filtered[query.offset : query.offset + query.limit]
        return {"items": items, "total": total, "limit": query.limit, "offset": query.offset, "source": "memory"}

    def list_alerts(self, query: AlertListQuery) -> dict[str, Any]:
        rows = list(self._sniffer_service.recent_alerts())

        def match(row: dict[str, Any]) -> bool:
            if query.src and query.src.lower() not in str(row.get("src") or "").lower():
                return False
            if query.dst and query.dst.lower() not in str(row.get("dst") or "").lower():
                return False
            if query.attack and query.attack.lower() not in str(row.get("attack_type") or "").lower():
                return False
            if query.proto and query.proto.lower() not in str(row.get("proto") or "").lower():
                return False
            if query.text:
                hay = " ".join(
                    [
                        str(row.get("detail") or ""),
                        str(row.get("attack_type") or ""),
                        str(row.get("remote_ip") or ""),
                        str(row.get("app_protocol") or ""),
                        str(row.get("dns_qname") or ""),
                        str(row.get("http_host") or ""),
                        str(row.get("http_path") or ""),
                        str(row.get("sni") or ""),
                    ]
                ).lower()
                if query.text.lower() not in hay:
                    return False
            if query.min_score:
                try:
                    if float(row.get("score") or 0.0) < float(query.min_score):
                        return False
                except (TypeError, ValueError):
                    pass
            if query.only_remote and not _is_remote_traffic(row):
                return False
            return True

        filtered = [dict(row) for row in rows if match(row)]
        total = len(filtered)
        items = filtered[query.offset : query.offset + query.limit]
        return {"items": items, "total": total, "limit": query.limit, "offset": query.offset, "source": "memory"}

    def get_packet_detail(self, packet_id: str) -> dict[str, Any] | None:
        rows = list(self._sniffer_service.recent_packets())
        for row in rows:
            if str(row.get("id") or "") == str(packet_id):
                return dict(row)
        return None

    def get_alert_detail(self, alert_id: str) -> dict[str, Any] | None:
        rows = list(self._sniffer_service.recent_alerts())
        for row in rows:
            if str(row.get("id") or "") == str(alert_id):
                return dict(row)
        return None


class SQLiteHistoryRepository(BaseHistoryRepository):
    def __init__(self, db_path: str = DB_PATH, connect_factory: Callable[[str], sqlite3.Connection] | None = None) -> None:
        self._db_path = db_path
        self._connect_factory = connect_factory or self._default_connect

    @staticmethod
    def _default_connect(db_path: str) -> sqlite3.Connection:
        return sqlite3.connect(db_path)

    @staticmethod
    def _configure_connection(conn: sqlite3.Connection) -> sqlite3.Connection:
        conn.create_function("netbot_is_remote_flow", 3, _sqlite_is_remote_flow)
        return conn

    @staticmethod
    async def _configure_async_connection(conn: aiosqlite.Connection) -> aiosqlite.Connection:
        await conn.create_function("netbot_is_remote_flow", 3, _sqlite_is_remote_flow)
        return conn

    def list_packets(self, query: PacketListQuery) -> dict[str, Any]:
        where, params = self._build_packet_where(query)

        try:
            conn = self._configure_connection(self._connect_factory(self._db_path))
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("History database is unavailable") from exc
        try:
            cur = conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM packets{where}", params)
            total = int(cur.fetchone()[0])
            cur.execute(
                "SELECT id, ts, src, dst, proto, sport, dport, length, country, org, summary, is_alert, remote_ip, app_protocol, app_category, app_confidence, l7, dns_qname, http_host, http_path, sni, tls_version "
                f"FROM packets{where} ORDER BY id DESC LIMIT ? OFFSET ?",
                [*params, query.limit, query.offset],
            )
            items = [self._normalize_packet_row(row) for row in cur.fetchall()]
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("Packet history query failed") from exc
        finally:
            conn.close()
        return {"items": items, "total": total, "limit": query.limit, "offset": query.offset, "source": "sqlite"}

    def list_alerts(self, query: AlertListQuery) -> dict[str, Any]:
        where, params = self._build_alert_where(query)

        try:
            conn = self._configure_connection(self._connect_factory(self._db_path))
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("History database is unavailable") from exc
        try:
            cur = conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM alerts{where}", params)
            total = int(cur.fetchone()[0])
            cur.execute(
                "SELECT id, ts, src, dst, proto, attack_type, score, detail, severity, engine, score_raw, incident_id, incident_count, incident_score, packet_id, remote_ip, app_protocol, app_category, app_confidence, dns_qname, http_host, http_path, sni "
                f"FROM alerts{where} ORDER BY id DESC LIMIT ? OFFSET ?",
                [*params, query.limit, query.offset],
            )
            items = [self._normalize_alert_row(row) for row in cur.fetchall()]
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("Alert history query failed") from exc
        finally:
            conn.close()
        return {"items": items, "total": total, "limit": query.limit, "offset": query.offset, "source": "sqlite"}

    async def alist_packets(self, query: PacketListQuery) -> dict[str, Any]:
        where, params = self._build_packet_where(query)
        try:
            async with aiosqlite.connect(self._db_path) as conn:
                await self._configure_async_connection(conn)
                total = int(await self._fetch_scalar_async(conn, f"SELECT COUNT(*) FROM packets{where}", params))
                rows = await self._fetch_rows_async(
                    conn,
                    "SELECT id, ts, src, dst, proto, sport, dport, length, country, org, summary, is_alert, remote_ip, app_protocol, app_category, app_confidence, l7, dns_qname, http_host, http_path, sni, tls_version "
                    f"FROM packets{where} ORDER BY id DESC LIMIT ? OFFSET ?",
                    [*params, query.limit, query.offset],
                )
        except aiosqlite.Error as exc:
            raise HistoryRepositoryError("Packet history query failed") from exc
        return {
            "items": [self._normalize_packet_row(row) for row in rows],
            "total": total,
            "limit": query.limit,
            "offset": query.offset,
            "source": "sqlite",
        }

    async def alist_alerts(self, query: AlertListQuery) -> dict[str, Any]:
        where, params = self._build_alert_where(query)
        try:
            async with aiosqlite.connect(self._db_path) as conn:
                await self._configure_async_connection(conn)
                total = int(await self._fetch_scalar_async(conn, f"SELECT COUNT(*) FROM alerts{where}", params))
                rows = await self._fetch_rows_async(
                    conn,
                    "SELECT id, ts, src, dst, proto, attack_type, score, detail, severity, engine, score_raw, incident_id, incident_count, incident_score, packet_id, remote_ip, app_protocol, app_category, app_confidence, dns_qname, http_host, http_path, sni "
                    f"FROM alerts{where} ORDER BY id DESC LIMIT ? OFFSET ?",
                    [*params, query.limit, query.offset],
                )
        except aiosqlite.Error as exc:
            raise HistoryRepositoryError("Alert history query failed") from exc
        return {
            "items": [self._normalize_alert_row(row) for row in rows],
            "total": total,
            "limit": query.limit,
            "offset": query.offset,
            "source": "sqlite",
        }

    def get_packet_detail(self, packet_id: str) -> dict[str, Any] | None:
        try:
            pid = int(packet_id)
        except (TypeError, ValueError):
            return None
        try:
            conn = self._configure_connection(self._connect_factory(self._db_path))
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("History database is unavailable") from exc
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, ts, src, dst, proto, sport, dport, length, country, org, summary, is_alert, remote_ip, app_protocol, app_category, app_confidence, l7, dns_qname, http_host, http_path, sni, tls_version "
                "FROM packets WHERE id = ?",
                (pid,),
            )
            row = cur.fetchone()
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("Packet detail query failed") from exc
        finally:
            conn.close()
        return self._normalize_packet_row(row) if row else None

    async def aget_packet_detail(self, packet_id: str) -> dict[str, Any] | None:
        try:
            pid = int(packet_id)
        except (TypeError, ValueError):
            return None
        try:
            async with aiosqlite.connect(self._db_path) as conn:
                await self._configure_async_connection(conn)
                row = await self._fetch_row_async(
                    conn,
                    "SELECT id, ts, src, dst, proto, sport, dport, length, country, org, summary, is_alert, remote_ip, app_protocol, app_category, app_confidence, l7, dns_qname, http_host, http_path, sni, tls_version "
                    "FROM packets WHERE id = ?",
                    (pid,),
                )
        except aiosqlite.Error as exc:
            raise HistoryRepositoryError("Packet detail query failed") from exc
        return self._normalize_packet_row(row) if row else None

    def get_alert_detail(self, alert_id: str) -> dict[str, Any] | None:
        try:
            aid = int(alert_id)
        except (TypeError, ValueError):
            return None
        try:
            conn = self._configure_connection(self._connect_factory(self._db_path))
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("History database is unavailable") from exc
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, ts, src, dst, proto, attack_type, score, detail, severity, engine, score_raw, incident_id, incident_count, incident_score, packet_id, remote_ip, app_protocol, app_category, app_confidence, dns_qname, http_host, http_path, sni "
                "FROM alerts WHERE id = ?",
                (aid,),
            )
            row = cur.fetchone()
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("Alert detail query failed") from exc
        finally:
            conn.close()
        return self._normalize_alert_row(row) if row else None

    async def aget_alert_detail(self, alert_id: str) -> dict[str, Any] | None:
        try:
            aid = int(alert_id)
        except (TypeError, ValueError):
            return None
        try:
            async with aiosqlite.connect(self._db_path) as conn:
                await self._configure_async_connection(conn)
                row = await self._fetch_row_async(
                    conn,
                    "SELECT id, ts, src, dst, proto, attack_type, score, detail, severity, engine, score_raw, incident_id, incident_count, incident_score, packet_id, remote_ip, app_protocol, app_category, app_confidence, dns_qname, http_host, http_path, sni "
                    "FROM alerts WHERE id = ?",
                    (aid,),
                )
        except aiosqlite.Error as exc:
            raise HistoryRepositoryError("Alert detail query failed") from exc
        return self._normalize_alert_row(row) if row else None

    @staticmethod
    def _build_packet_where(query: PacketListQuery) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if query.src:
            clauses.append("src LIKE ?")
            params.append(f"%{query.src}%")
        if query.dst:
            clauses.append("dst LIKE ?")
            params.append(f"%{query.dst}%")
        if query.proto:
            clauses.append("proto LIKE ?")
            params.append(f"%{query.proto}%")
        if query.text:
            clauses.append("(summary LIKE ? OR org LIKE ? OR country LIKE ? OR remote_ip LIKE ? OR app_protocol LIKE ? OR l7 LIKE ? OR dns_qname LIKE ? OR http_host LIKE ? OR http_path LIKE ? OR sni LIKE ?)")
            params.extend([f"%{query.text}%"] * 10)
        if query.only_alerts:
            clauses.append("is_alert = 1")
        if query.only_remote:
            clauses.append(_sqlite_remote_clause())
        return (f" WHERE {' AND '.join(clauses)}" if clauses else "", params)

    @staticmethod
    def _build_alert_where(query: AlertListQuery) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if query.src:
            clauses.append("src LIKE ?")
            params.append(f"%{query.src}%")
        if query.dst:
            clauses.append("dst LIKE ?")
            params.append(f"%{query.dst}%")
        if query.attack:
            clauses.append("attack_type LIKE ?")
            params.append(f"%{query.attack}%")
        if query.proto:
            clauses.append("proto LIKE ?")
            params.append(f"%{query.proto}%")
        if query.text:
            clauses.append("(detail LIKE ? OR attack_type LIKE ? OR remote_ip LIKE ? OR app_protocol LIKE ? OR dns_qname LIKE ? OR http_host LIKE ? OR http_path LIKE ? OR sni LIKE ?)")
            params.extend([f"%{query.text}%"] * 8)
        if query.min_score:
            try:
                clauses.append("score >= ?")
                params.append(float(query.min_score))
            except (TypeError, ValueError):
                pass
        if query.only_remote:
            clauses.append(_sqlite_remote_clause())
        return (f" WHERE {' AND '.join(clauses)}" if clauses else "", params)

    @staticmethod
    async def _fetch_scalar_async(conn: aiosqlite.Connection, sql: str, params: list[Any]) -> Any:
        cursor = await conn.execute(sql, params)
        try:
            row = await cursor.fetchone()
        finally:
            await cursor.close()
        return row[0] if row else 0

    @staticmethod
    async def _fetch_rows_async(conn: aiosqlite.Connection, sql: str, params: list[Any]) -> list[tuple[Any, ...]]:
        cursor = await conn.execute(sql, params)
        try:
            return await cursor.fetchall()
        finally:
            await cursor.close()

    @staticmethod
    async def _fetch_row_async(conn: aiosqlite.Connection, sql: str, params: tuple[Any, ...]) -> tuple[Any, ...] | None:
        cursor = await conn.execute(sql, params)
        try:
            return await cursor.fetchone()
        finally:
            await cursor.close()

    @staticmethod
    def _normalize_packet_row(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "id": row[0],
            "ts": row[1],
            "src": row[2],
            "dst": row[3],
            "proto": row[4],
            "sport": row[5],
            "dport": row[6],
            "length": row[7],
            "country": row[8],
            "org": row[9],
            "summary": row[10],
            "is_alert": bool(row[11]),
            "remote_ip": _preferred_remote_ip(row, remote_index=12, src_index=2, dst_index=3),
            "app_protocol": row[13],
            "app_category": row[14],
            "app_confidence": row[15],
            "l7": row[16],
            "dns_qname": row[17],
            "http_host": row[18],
            "http_path": row[19],
            "sni": row[20],
            "tls_version": row[21],
        }

    @staticmethod
    def _normalize_alert_row(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "id": row[0],
            "ts": row[1],
            "src": row[2],
            "dst": row[3],
            "proto": row[4],
            "attack_type": row[5],
            "score": row[6],
            "detail": row[7],
            "severity": row[8],
            "engine": row[9],
            "score_raw": row[10],
            "incident_id": row[11],
            "incident_count": row[12],
            "incident_score": row[13],
            "packet_id": row[14],
            "remote_ip": _preferred_remote_ip(row, remote_index=15, src_index=2, dst_index=3),
            "app_protocol": row[16],
            "app_category": row[17],
            "app_confidence": row[18],
            "dns_qname": row[19],
            "http_host": row[20],
            "http_path": row[21],
            "sni": row[22],
        }
