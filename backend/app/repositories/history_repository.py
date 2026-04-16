from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
import hashlib
import sqlite3
from typing import Any, Callable, Protocol

try:
    import aiosqlite  # type: ignore
except ModuleNotFoundError:
    # Keep async history paths usable in environments where aiosqlite is absent.
    class _AioSQLiteCursorShim:
        def __init__(self, cursor: sqlite3.Cursor) -> None:
            self._cursor = cursor

        async def fetchone(self) -> Any:
            return self._cursor.fetchone()

        async def fetchall(self) -> list[Any]:
            return self._cursor.fetchall()

        async def close(self) -> None:
            self._cursor.close()

    class _AioSQLiteConnectionShim:
        def __init__(self, db_path: str, *args: Any, **kwargs: Any) -> None:
            self._conn = sqlite3.connect(db_path, *args, **kwargs)

        @property
        def row_factory(self) -> Any:
            return self._conn.row_factory

        @row_factory.setter
        def row_factory(self, value: Any) -> None:
            self._conn.row_factory = value

        async def __aenter__(self) -> "_AioSQLiteConnectionShim":
            return self

        async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
            self._conn.close()

        async def create_function(self, *args: Any) -> None:
            self._conn.create_function(*args)

        async def execute(self, sql: str, params: Any = None) -> _AioSQLiteCursorShim:
            cursor = self._conn.cursor()
            cursor.execute(sql, params or [])
            return _AioSQLiteCursorShim(cursor)

    class _AioSQLiteShim:
        Connection = _AioSQLiteConnectionShim
        Error = sqlite3.Error

        @staticmethod
        def connect(db_path: str, *args: Any, **kwargs: Any) -> _AioSQLiteConnectionShim:
            return _AioSQLiteConnectionShim(db_path, *args, **kwargs)

    aiosqlite = _AioSQLiteShim()

from backend.app.bootstrap import ensure_project_root_on_path

ensure_project_root_on_path()

from backend.app.services.app_protocols import infer_app_protocol
from core.netbotpro_sniffer_core.ip_utils import is_local_ip, is_public_ip, is_remote_ip, preferred_remote_ip
from log_manager import DB_PATH  # noqa: E402


class HistoryRepositoryError(RuntimeError):
    pass


_CONTEXT_PACKET_LIMIT = 500
_CONTEXT_ALERT_LIMIT = 250


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


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_proto(value: Any) -> str:
    text = _normalize_text(value).upper()
    return text or "OTHER"


def _safe_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = _normalize_text(value).lower()
    if text in {"1", "true", "yes"}:
        return True
    if text in {"0", "false", "no"}:
        return False
    try:
        return bool(int(value))
    except (TypeError, ValueError):
        return None


def _row_get(row: Any, key: str, default: Any = None) -> Any:
    if row is None:
        return default
    if hasattr(row, "keys"):
        try:
            return row[key] if key in row.keys() else default
        except Exception:
            return default
    if isinstance(row, dict):
        return row.get(key, default)
    return default


def _normalize_alpn(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip() for item in value if str(item).strip()]
    text = _normalize_text(value)
    if not text:
        return []
    return [item.strip() for item in text.split(",") if item.strip()]


def _serialize_alpn(value: Any) -> str | None:
    items = _normalize_alpn(value)
    return ", ".join(items) if items else None


def _parse_timestamp_seconds(value: Any) -> float | None:
    text = _normalize_text(value)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        pass
    try:
        parsed = datetime.strptime(text, "%H:%M:%S")
    except ValueError:
        return None
    return float(parsed.hour * 3600 + parsed.minute * 60 + parsed.second)


def _flow_identity(row: dict[str, Any]) -> dict[str, Any]:
    src = _normalize_text(row.get("src"))
    dst = _normalize_text(row.get("dst"))
    remote_ip = _preferred_remote_ip(row) or _normalize_text(row.get("remote_ip"))
    proto = _normalize_proto(row.get("proto"))
    sport = _safe_int(row.get("sport"))
    dport = _safe_int(row.get("dport"))
    direction = _normalize_text(row.get("direction")).upper()
    src_local = _is_local_ip(src)
    dst_local = _is_local_ip(dst)

    if direction == "INCOMING":
        local_ip = dst or src or "-"
        remote_endpoint = src or remote_ip or dst or "-"
        local_port = dport
        remote_port = sport
    elif direction == "OUTGOING":
        local_ip = src or dst or "-"
        remote_endpoint = dst or remote_ip or src or "-"
        local_port = sport
        remote_port = dport
    elif remote_ip and remote_ip == src:
        direction = "INCOMING"
        local_ip = dst or src or "-"
        remote_endpoint = src
        local_port = dport
        remote_port = sport
    elif remote_ip and remote_ip == dst:
        direction = "OUTGOING"
        local_ip = src or dst or "-"
        remote_endpoint = dst
        local_port = sport
        remote_port = dport
    elif src_local and not dst_local:
        direction = "OUTGOING"
        local_ip = src or "-"
        remote_endpoint = dst or remote_ip or "-"
        local_port = sport
        remote_port = dport
    elif dst_local and not src_local:
        direction = "INCOMING"
        local_ip = dst or "-"
        remote_endpoint = src or remote_ip or "-"
        local_port = dport
        remote_port = sport
    else:
        local_ip = src or "-"
        remote_endpoint = dst or remote_ip or "-"
        local_port = sport
        remote_port = dport
        if not direction:
            direction = "LOCAL" if src_local and dst_local else "UNKNOWN"

    flow_key = f"{proto}|{local_ip or '-'}|{local_port or '-'}|{remote_endpoint or '-'}|{remote_port or '-'}"
    return {
        "proto": proto,
        "direction": direction,
        "local_ip": local_ip or "-",
        "remote_ip": remote_endpoint or "-",
        "local_port": local_port,
        "remote_port": remote_port,
        "flow_key": flow_key,
        "flow_id": f"flow-{hashlib.sha1(flow_key.encode('utf-8')).hexdigest()[:12]}",
        "conversation_key": f"{local_ip or '-'}:{local_port or '-'} <-> {remote_endpoint or '-'}:{remote_port or '-'} ({proto})",
    }


def _same_peer_signature(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return (
        left.get("proto") == right.get("proto")
        and left.get("local_ip") == right.get("local_ip")
        and left.get("remote_ip") == right.get("remote_ip")
    )


def _same_flow_signature(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return _same_peer_signature(left, right) and left.get("local_port") == right.get("local_port") and left.get("remote_port") == right.get("remote_port")


def _same_port_context(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if not _same_peer_signature(left, right):
        return False
    shared_ports = {port for port in (right.get("local_port"), right.get("remote_port")) if port is not None}
    return any(port in shared_ports for port in (left.get("local_port"), left.get("remote_port")))


def _packet_preview(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "capture_id": row.get("capture_id"),
        "ts": row.get("ts"),
        "src": row.get("src"),
        "dst": row.get("dst"),
        "proto": row.get("proto"),
        "sport": row.get("sport"),
        "dport": row.get("dport"),
        "length": row.get("length"),
        "summary": row.get("summary"),
        "process_name": row.get("process_name"),
        "pid": row.get("pid"),
        "is_alert": bool(row.get("is_alert")),
    }


def _alert_preview(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "ts": row.get("ts"),
        "attack_type": row.get("attack_type"),
        "severity": row.get("severity"),
        "score": row.get("score"),
        "detail": row.get("detail"),
        "src": row.get("src"),
        "dst": row.get("dst"),
        "proto": row.get("proto"),
        "packet_id": row.get("packet_id"),
        "process_name": row.get("process_name"),
        "pid": row.get("pid"),
        "incident_id": row.get("incident_id"),
        "engine": row.get("engine"),
    }


def _sort_rows_by_time(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def sort_key(row: dict[str, Any]) -> tuple[float, str]:
        ts_value = _parse_timestamp_seconds(row.get("ts"))
        numeric_ts = ts_value if ts_value is not None else float("-inf")
        return (numeric_ts, _normalize_text(row.get("id")))

    return sorted(rows, key=sort_key, reverse=True)


def _confidence_rank(value: Any) -> int:
    text = _normalize_text(value).lower()
    if text == "high":
        return 3
    if text == "medium":
        return 2
    if text == "low":
        return 1
    return 0


def _prefer_protocol(current: Any, computed: Any) -> bool:
    current_text = _normalize_text(current).upper()
    computed_text = _normalize_text(computed).upper()
    if not computed_text:
        return False
    if current_text in {"", "TCP", "UDP", "ICMP", "OTHER"}:
        return True
    return current_text == computed_text


def _enrich_protocol_metadata(row: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(row)
    if "tls_alpn" in enriched:
        enriched["tls_alpn"] = _normalize_alpn(enriched.get("tls_alpn"))
    computed = infer_app_protocol(enriched)

    if _prefer_protocol(enriched.get("app_protocol"), computed.get("app_protocol")):
        enriched["app_protocol"] = computed.get("app_protocol")
        enriched["app_category"] = computed.get("app_category")
        if _confidence_rank(computed.get("app_confidence")) >= _confidence_rank(enriched.get("app_confidence")):
            enriched["app_confidence"] = computed.get("app_confidence")
    elif not _normalize_text(enriched.get("app_category")) and computed.get("app_category"):
        enriched["app_category"] = computed.get("app_category")

    for key in (
        "protocol_basis",
        "protocol_notes",
        "protocol_handshake",
        "protocol_unusual_port",
        "payload_binary_like",
        "payload_entropy",
        "payload_printable_ratio",
    ):
        current_value = enriched.get(key)
        if current_value in (None, "", []):
            enriched[key] = computed.get(key)

    if enriched.get("protocol_unusual_port") is not None:
        enriched["protocol_unusual_port"] = bool(_bool_or_none(enriched.get("protocol_unusual_port")))
    if enriched.get("payload_binary_like") is not None:
        enriched["payload_binary_like"] = bool(_bool_or_none(enriched.get("payload_binary_like")))
    if enriched.get("payload_entropy") is not None:
        enriched["payload_entropy"] = _safe_float(enriched.get("payload_entropy"))
    if enriched.get("payload_printable_ratio") is not None:
        enriched["payload_printable_ratio"] = _safe_float(enriched.get("payload_printable_ratio"))
    return enriched


def _flow_alert_match(alert: dict[str, Any], peer_identity: dict[str, Any], flow_packet_ids: set[str]) -> bool:
    packet_id = _normalize_text(alert.get("packet_id"))
    if packet_id and packet_id in flow_packet_ids:
        return True
    return _same_peer_signature(_flow_identity(alert), peer_identity)


def _same_remote_activity(
    selected_identity: dict[str, Any],
    packet_rows: list[dict[str, Any]],
    alert_rows: list[dict[str, Any]],
    *,
    selected_packet_id: str = "",
    selected_alert_id: str = "",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    same_remote_packets = [
        _packet_preview(row)
        for row in _sort_rows_by_time([dict(row) for row in packet_rows if _flow_identity(row)["remote_ip"] == selected_identity["remote_ip"]])
        if _normalize_text(row.get("id")) != selected_packet_id
    ][:5]
    same_remote_alerts = [
        _alert_preview(row)
        for row in _sort_rows_by_time([dict(row) for row in alert_rows if _flow_identity(row)["remote_ip"] == selected_identity["remote_ip"]])
        if _normalize_text(row.get("id")) != selected_alert_id
    ][:5]
    return same_remote_packets, same_remote_alerts


def _related_flows(selected_identity: dict[str, Any], packet_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    clusters: dict[str, dict[str, Any]] = {}
    for row in packet_rows:
        identity = _flow_identity(row)
        if identity["flow_id"] == selected_identity["flow_id"]:
            continue
        if identity["local_ip"] != selected_identity["local_ip"] and identity["remote_ip"] != selected_identity["remote_ip"]:
            continue
        cluster = clusters.setdefault(
            identity["flow_id"],
            {
                "conversation_key": identity["conversation_key"],
                "flow_id": identity["flow_id"],
                "direction": identity["direction"],
                "packets_total": 0,
                "remote_ip": identity["remote_ip"],
                "ports": set(),
            },
        )
        cluster["packets_total"] += 1
        if identity["remote_port"] is not None:
            cluster["ports"].add(identity["remote_port"])

    items = []
    for cluster in sorted(clusters.values(), key=lambda item: item["packets_total"], reverse=True)[:5]:
        ports = ", ".join(str(port) for port in sorted(cluster["ports"])) or "-"
        items.append(
            {
                "title": cluster["conversation_key"],
                "body": f"{cluster['packets_total']} packets | {cluster['direction'].title() if cluster['direction'] else 'Unknown'} | remote {cluster['remote_ip']} | ports {ports}",
            }
        )
    return items


def _alert_correlation_summary(flow_alerts: list[dict[str, Any]], pair_alerts: list[dict[str, Any]], same_remote_alerts: list[dict[str, Any]]) -> dict[str, Any]:
    engines = _unique_non_empty([row.get("engine") for row in pair_alerts])
    attack_types = _unique_non_empty([row.get("attack_type") for row in pair_alerts])
    incident_ids = _unique_non_empty([row.get("incident_id") for row in pair_alerts])
    return {
        "flow_alerts_total": len(flow_alerts),
        "peer_alerts_total": len(pair_alerts),
        "same_remote_alerts_total": len(same_remote_alerts),
        "engines": engines,
        "attack_types": attack_types,
        "incident_ids": incident_ids,
    }


def _root_cause_groups(
    *,
    process_correlation: dict[str, Any],
    alert_correlation: dict[str, Any],
    behavior_labels: list[str],
    related_flows: list[dict[str, Any]],
    linked_packet: dict[str, Any] | None = None,
    alert: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    if linked_packet is not None and alert is not None:
        groups.append(
            {
                "title": "Packet to Alert Chain",
                "body": f"Alert {alert.get('attack_type') or 'Alert'} links to packet {linked_packet.get('id') or linked_packet.get('capture_id') or '-'} on {linked_packet.get('proto') or '-'} {linked_packet.get('sport') or '-'}->{linked_packet.get('dport') or '-'}.",
            }
        )
    if int(alert_correlation.get("flow_alerts_total") or 0) > 0:
        groups.append(
            {
                "title": "Flow-linked Detections",
                "body": f"{alert_correlation['flow_alerts_total']} alert(s) were observed on the same flow; attack types: {', '.join(alert_correlation.get('attack_types') or ['-'])}.",
            }
        )
    if int(alert_correlation.get("peer_alerts_total") or 0) > int(alert_correlation.get("flow_alerts_total") or 0):
        groups.append(
            {
                "title": "Remote Host Recurrence",
                "body": f"The same peer triggered {alert_correlation['peer_alerts_total']} alert(s) across the current context window.",
            }
        )
    if process_correlation.get("available") and int(process_correlation.get("alerts_total") or 0) > 0:
        groups.append(
            {
                "title": "Process-linked Activity",
                "body": f"{process_correlation.get('label') or 'Process'} appears in {process_correlation.get('sessions_total') or 0} sessions and {process_correlation.get('alerts_total') or 0} alert(s).",
            }
        )
    if behavior_labels:
        groups.append(
            {
                "title": "Behavior Pattern",
                "body": f"Observed pattern(s): {', '.join(behavior_labels)}.",
            }
        )
    if related_flows:
        groups.append(
            {
                "title": "Related Flow Cluster",
                "body": f"{len(related_flows)} additional flow(s) share the same host or remote context in the current sample.",
            }
        )
    return groups[:5]


def _build_packet_flow_context(packet: dict[str, Any], packet_rows: list[dict[str, Any]], alert_rows: list[dict[str, Any]], *, source: str) -> dict[str, Any]:
    selected_identity = _flow_identity(packet)
    pair_packets = [dict(row) for row in packet_rows if _same_peer_signature(_flow_identity(row), selected_identity)]
    flow_packets = [row for row in pair_packets if _same_flow_signature(_flow_identity(row), selected_identity)]
    same_port_packets = [row for row in pair_packets if _same_port_context(_flow_identity(row), selected_identity)]

    sorted_flow_packets = _sort_rows_by_time(flow_packets)
    flow_packet_ids = {_normalize_text(row.get("id")) for row in sorted_flow_packets if _normalize_text(row.get("id"))}
    selected_packet_id = _normalize_text(packet.get("id"))

    pair_alerts = [dict(row) for row in alert_rows if _same_peer_signature(_flow_identity(row), selected_identity)]
    flow_alerts = [row for row in pair_alerts if _flow_alert_match(row, selected_identity, flow_packet_ids)]
    sorted_flow_alerts = _sort_rows_by_time(flow_alerts)

    bytes_in = 0
    bytes_out = 0
    timestamps = []
    for row in sorted_flow_packets:
        identity = _flow_identity(row)
        packet_length = _safe_int(row.get("length")) or 0
        if identity.get("direction") == "INCOMING":
            bytes_in += packet_length
        else:
            bytes_out += packet_length
        ts_value = _parse_timestamp_seconds(row.get("ts"))
        if ts_value is not None:
            timestamps.append(ts_value)

    related_packets = [_packet_preview(row) for row in sorted_flow_packets if _normalize_text(row.get("id")) != selected_packet_id][:5]
    related_alerts = [_alert_preview(row) for row in sorted_flow_alerts][:5]
    same_remote_packets, same_remote_alerts = _same_remote_activity(
        selected_identity,
        packet_rows,
        alert_rows,
        selected_packet_id=selected_packet_id,
    )
    first_seen = sorted_flow_packets[-1].get("ts") if sorted_flow_packets else packet.get("ts")
    last_seen = sorted_flow_packets[0].get("ts") if sorted_flow_packets else packet.get("ts")
    duration_ms = 0
    if timestamps:
        duration_ms = int(max(0.0, (max(timestamps) - min(timestamps)) * 1000.0))

    process_correlation = _process_correlation(packet, packet_rows, alert_rows)
    behavior_labels = _behavior_labels(packet, packet_rows, selected_identity, sorted_flow_packets)
    related_flows = _related_flows(selected_identity, packet_rows)
    alert_correlation = _alert_correlation_summary(sorted_flow_alerts, pair_alerts, same_remote_alerts)
    root_cause_groups = _root_cause_groups(
        process_correlation=process_correlation,
        alert_correlation=alert_correlation,
        behavior_labels=behavior_labels,
        related_flows=related_flows,
    )

    return {
        "source": source,
        "flow_id": selected_identity.get("flow_id"),
        "conversation_key": selected_identity.get("conversation_key"),
        "direction": selected_identity.get("direction"),
        "local_ip": selected_identity.get("local_ip"),
        "remote_ip": selected_identity.get("remote_ip"),
        "local_port": selected_identity.get("local_port"),
        "remote_port": selected_identity.get("remote_port"),
        "flow_packets_total": len(sorted_flow_packets) or 1,
        "flow_alerts_total": len(sorted_flow_alerts),
        "flow_bytes_in": bytes_in,
        "flow_bytes_out": bytes_out,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "duration_ms": duration_ms,
        "same_peer_packets_total": len(pair_packets),
        "same_peer_alerts_total": len(pair_alerts),
        "same_port_packets_total": len(same_port_packets),
        "sample_packets": len(packet_rows),
        "sample_alerts": len(alert_rows),
        "related_packets": related_packets,
        "related_alerts": related_alerts,
        "same_remote_packets": same_remote_packets,
        "same_remote_alerts": same_remote_alerts,
        "related_flows": related_flows,
        "alert_correlation": alert_correlation,
        "root_cause_groups": root_cause_groups,
        "behavior_labels": behavior_labels,
        "process_correlation": process_correlation,
        "host_correlation": _host_correlation(packet, packet_rows),
        "port_correlation": _port_correlation(packet, packet_rows),
        "conversation_clusters": _conversation_clusters(packet, packet_rows),
    }


def _process_key(row: dict[str, Any]) -> tuple[str, str]:
    return (_normalize_text(row.get("pid")), _normalize_text(row.get("process_name")))


def _unique_non_empty(values: list[Any]) -> list[str]:
    return sorted({str(value).strip() for value in values if str(value or "").strip() and str(value or "").strip() != "-"})


def _first_present(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", "-"):
            return value
    return None


def _context_match_values(identity: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("local_ip", "remote_ip"):
        value = _normalize_text(identity.get(key))
        if value and value != "-" and value not in values:
            values.append(value)
    return values


def _context_where_clause(identity: dict[str, Any], *, include_remote_column: bool = True) -> tuple[str, list[Any]]:
    values = _context_match_values(identity)
    if not values:
        return "1 = 0", []

    placeholders = ", ".join("?" for _ in values)
    clauses = [f"src IN ({placeholders})", f"dst IN ({placeholders})"]
    params: list[Any] = [*values, *values]
    if include_remote_column:
        clauses.append(f"remote_ip IN ({placeholders})")
        params.extend(values)
    return f"({' OR '.join(clauses)})", params


def _process_correlation(packet: dict[str, Any], packet_rows: list[dict[str, Any]], alert_rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    pid, process_name = _process_key(packet)
    attribution_confidence = _normalize_text(_first_present(packet, "attribution_confidence")) or "unavailable"
    reason_unavailable = _normalize_text(_first_present(packet, "attribution_reason_unavailable")) or "Process metadata is unavailable for this packet or not persisted in history."
    attribution_source = _normalize_text(_first_present(packet, "attribution_source")) or "unavailable"
    parent_pid = _first_present(packet, "parent_pid")
    parent_process_name = _normalize_text(_first_present(packet, "parent_process_name"))
    executable_path = _normalize_text(_first_present(packet, "executable_path"))
    if not pid and not process_name:
        return {
            "available": False,
            "label": "Unknown process",
            "pid": None,
            "parent_pid": parent_pid,
            "parent_process_name": parent_process_name or None,
            "executable_path": executable_path or None,
            "attribution_confidence": attribution_confidence,
            "attribution_source": attribution_source,
            "reason_unavailable": reason_unavailable,
            "packets_total": 0,
            "alerts_total": 0,
            "sessions_total": 0,
            "ports_total": 0,
            "remote_hosts_total": 0,
            "pattern": "Unavailable",
            "flow_samples": [],
            "related_packets": [],
            "related_alerts": [],
        }

    def same_process(row: dict[str, Any]) -> bool:
        row_pid, row_name = _process_key(row)
        if pid and row_pid:
            return row_pid == pid
        if process_name and row_name:
            return row_name.lower() == process_name.lower()
        return False

    rows = [dict(row) for row in packet_rows if same_process(row)]
    process_alerts = [dict(row) for row in (alert_rows or []) if same_process(row)]
    identities = [_flow_identity(row) for row in rows]
    sessions_total = len({identity["flow_id"] for identity in identities})
    unique_ports = _unique_non_empty([identity["local_port"] for identity in identities] + [identity["remote_port"] for identity in identities])
    remote_hosts = _unique_non_empty([identity["remote_ip"] for identity in identities])
    flow_samples = []
    for identity in identities[:4]:
        flow_samples.append(
            {
                "title": identity["conversation_key"],
                "body": f"{identity['direction'].title() if identity['direction'] else 'Unknown'} session",
            }
        )

    pattern = "Single-session process activity"
    if sessions_total >= 3 and len(unique_ports) >= 3 and len(remote_hosts) >= 3:
        pattern = "Multi-port multi-host process activity"
    elif sessions_total >= 3:
        pattern = "Process appears across multiple sessions"

    selected_packet_id = _normalize_text(packet.get("id"))
    related_packets = [_packet_preview(row) for row in _sort_rows_by_time(rows) if _normalize_text(row.get("id")) != selected_packet_id][:5]
    related_alerts = [_alert_preview(row) for row in _sort_rows_by_time(process_alerts)][:5]

    return {
        "available": True,
        "label": process_name or f"PID {pid}",
        "pid": pid or None,
        "parent_pid": parent_pid,
        "parent_process_name": parent_process_name or None,
        "executable_path": executable_path or None,
        "attribution_confidence": attribution_confidence if attribution_confidence != "unavailable" else "medium",
        "attribution_source": attribution_source if attribution_source != "unavailable" else None,
        "reason_unavailable": None,
        "packets_total": len(rows),
        "alerts_total": len(process_alerts),
        "sessions_total": sessions_total,
        "ports_total": len(unique_ports),
        "remote_hosts_total": len(remote_hosts),
        "pattern": pattern,
        "flow_samples": flow_samples,
        "related_packets": related_packets,
        "related_alerts": related_alerts,
    }


def _host_correlation(packet: dict[str, Any], packet_rows: list[dict[str, Any]]) -> dict[str, Any]:
    selected_identity = _flow_identity(packet)
    host_packets = [dict(row) for row in packet_rows if _flow_identity(row)["local_ip"] == selected_identity["local_ip"]]
    identities = [_flow_identity(row) for row in host_packets]
    unique_remotes = _unique_non_empty([identity["remote_ip"] for identity in identities])
    unique_sessions = {identity["flow_id"] for identity in identities}
    unique_remote_ports = _unique_non_empty([identity["remote_port"] for identity in identities])
    selected_remote_sessions = len({identity["flow_id"] for identity in identities if identity["remote_ip"] == selected_identity["remote_ip"]})

    timestamps = [_parse_timestamp_seconds(row.get("ts")) for row in host_packets]
    timestamps = [value for value in timestamps if value is not None]
    burst_packets = 0
    if timestamps:
        latest = max(timestamps)
        burst_packets = sum(1 for value in timestamps if latest - value <= 10.0)

    pattern = "Focused host activity"
    if len(unique_remotes) >= 5:
        pattern = "Fan-out pattern observed"
    elif burst_packets >= 6:
        pattern = "Burst pattern observed"
    elif selected_remote_sessions >= 3:
        pattern = "Remote peer appears across multiple sessions"

    return {
        "local_ip": selected_identity["local_ip"],
        "remote_hosts_total": len(unique_remotes),
        "sessions_total": len(unique_sessions),
        "remote_ports_total": len(unique_remote_ports),
        "selected_remote_sessions_total": selected_remote_sessions,
        "burst_packets_10s": burst_packets,
        "pattern": pattern,
    }


def _port_correlation(packet: dict[str, Any], packet_rows: list[dict[str, Any]]) -> dict[str, Any]:
    selected_identity = _flow_identity(packet)
    host_packets = [
        dict(row)
        for row in packet_rows
        if _flow_identity(row)["local_ip"] == selected_identity["local_ip"] and _flow_identity(row)["proto"] == selected_identity["proto"]
    ]
    identities = [_flow_identity(row) for row in host_packets]
    local_port = selected_identity["local_port"]
    remote_port = selected_identity["remote_port"]

    same_local_port = [identity for identity in identities if local_port is not None and identity["local_port"] == local_port]
    same_remote_port = [identity for identity in identities if remote_port is not None and identity["remote_port"] == remote_port]
    local_port_sessions = len({identity["flow_id"] for identity in same_local_port})
    local_port_remotes = len({identity["remote_ip"] for identity in same_local_port})
    remote_port_sessions = len({identity["flow_id"] for identity in same_remote_port})
    remote_port_remotes = len({identity["remote_ip"] for identity in same_remote_port})

    pattern = "Port usage stays narrow"
    if remote_port_remotes >= 4:
        pattern = "Sweep pattern candidate"
    elif local_port_sessions >= 3:
        pattern = "Local port reuse across sessions"
    elif remote_port_sessions >= 3:
        pattern = "Remote service reuse across sessions"

    return {
        "local_port": local_port,
        "remote_port": remote_port,
        "local_port_sessions_total": local_port_sessions,
        "local_port_remote_hosts_total": local_port_remotes,
        "remote_port_sessions_total": remote_port_sessions,
        "remote_port_remote_hosts_total": remote_port_remotes,
        "pattern": pattern,
    }


def _conversation_clusters(packet: dict[str, Any], packet_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected_identity = _flow_identity(packet)
    host_packets = [dict(row) for row in packet_rows if _flow_identity(row)["local_ip"] == selected_identity["local_ip"]]
    clusters: dict[tuple[str, str], dict[str, Any]] = {}

    for row in host_packets:
        identity = _flow_identity(row)
        cluster_key = (identity["proto"], identity["remote_ip"])
        cluster = clusters.setdefault(
            cluster_key,
            {
                "proto": identity["proto"],
                "remote_ip": identity["remote_ip"],
                "session_ids": set(),
                "packets_total": 0,
                "ports": set(),
            },
        )
        cluster["session_ids"].add(identity["flow_id"])
        cluster["packets_total"] += 1
        if identity["remote_port"] is not None:
            cluster["ports"].add(identity["remote_port"])

    items = []
    for cluster in sorted(clusters.values(), key=lambda item: (len(item["session_ids"]), item["packets_total"]), reverse=True)[:5]:
        ports = ", ".join(str(port) for port in sorted(cluster["ports"])) or "-"
        items.append(
            {
                "title": f"{cluster['remote_ip']} ({cluster['proto']})",
                "body": f"{len(cluster['session_ids'])} sessions | {cluster['packets_total']} packets | ports {ports}",
            }
        )
    return items


def _behavior_labels(packet: dict[str, Any], packet_rows: list[dict[str, Any]], selected_identity: dict[str, Any], flow_packets: list[dict[str, Any]]) -> list[str]:
    labels: list[str] = []
    host = _host_correlation(packet, packet_rows)
    port = _port_correlation(packet, packet_rows)
    process = _process_correlation(packet, packet_rows)
    if host.get("pattern") and host["pattern"] not in {"Focused host activity"}:
        labels.append(str(host["pattern"]))
    if port.get("pattern") and port["pattern"] not in {"Port usage stays narrow"}:
        labels.append(str(port["pattern"]))
    if process.get("available") and process.get("pattern") and process["pattern"] not in {"Single-session process activity"}:
        labels.append(str(process["pattern"]))
    duration_candidates = [_parse_timestamp_seconds(row.get("ts")) for row in flow_packets]
    duration_candidates = [value for value in duration_candidates if value is not None]
    if len(flow_packets) >= 6 and duration_candidates and max(duration_candidates) - min(duration_candidates) <= 30.0:
        labels.append("Burst pattern observed")
    return labels[:5]


def _find_linked_packet(alert: dict[str, Any], packet_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    packet_ref = _normalize_text(alert.get("packet_id"))
    if packet_ref:
        for row in packet_rows:
            if packet_ref in {_normalize_text(row.get("capture_id")), _normalize_text(row.get("id"))}:
                return dict(row)

    proto = _normalize_proto(alert.get("proto"))
    src = _normalize_text(alert.get("src"))
    dst = _normalize_text(alert.get("dst"))
    alert_ts = _parse_timestamp_seconds(alert.get("ts"))
    candidates = []
    for row in packet_rows:
        if _normalize_proto(row.get("proto")) != proto:
            continue
        row_src = _normalize_text(row.get("src"))
        row_dst = _normalize_text(row.get("dst"))
        if (row_src, row_dst) != (src, dst) and (row_src, row_dst) != (dst, src):
            continue
        row_ts = _parse_timestamp_seconds(row.get("ts"))
        delta = abs((row_ts or 0.0) - (alert_ts or 0.0)) if row_ts is not None and alert_ts is not None else 0.0
        candidates.append((delta, dict(row)))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1]


def _build_alert_investigation_context(
    alert: dict[str, Any],
    packet_rows: list[dict[str, Any]],
    alert_rows: list[dict[str, Any]],
    *,
    source: str,
) -> dict[str, Any]:
    linked_packet = _find_linked_packet(alert, packet_rows)
    anchor = linked_packet or dict(alert)
    flow_context = _build_packet_flow_context(anchor, packet_rows, alert_rows, source=source)
    selected_alert_id = _normalize_text(alert.get("id"))
    selected_identity = _flow_identity(anchor)
    flow_packets = [dict(row) for row in packet_rows if _same_flow_signature(_flow_identity(row), selected_identity)]
    flow_packet_ids = {_normalize_text(row.get("id")) for row in flow_packets if _normalize_text(row.get("id"))}
    same_remote_packets, same_remote_alerts = _same_remote_activity(
        selected_identity,
        packet_rows,
        alert_rows,
        selected_packet_id=_normalize_text(linked_packet.get("id")) if linked_packet else "",
        selected_alert_id=selected_alert_id,
    )
    pair_alerts = [dict(row) for row in alert_rows if _same_peer_signature(_flow_identity(row), selected_identity)]
    flow_alerts = [row for row in pair_alerts if _flow_alert_match(row, selected_identity, flow_packet_ids)]
    sorted_flow_alerts = _sort_rows_by_time(flow_alerts)
    related_alerts = [_alert_preview(row) for row in sorted_flow_alerts if _normalize_text(row.get("id")) != selected_alert_id][:5]
    related_packets = flow_context.get("related_packets") or []
    process_correlation = flow_context.get("process_correlation") or {}
    related_flows = flow_context.get("related_flows") or []
    alert_correlation = _alert_correlation_summary(sorted_flow_alerts, pair_alerts, same_remote_alerts)
    root_cause_groups = _root_cause_groups(
        process_correlation=process_correlation,
        alert_correlation=alert_correlation,
        behavior_labels=list(flow_context.get("behavior_labels") or []),
        related_flows=related_flows,
        linked_packet=linked_packet,
        alert=alert,
    )

    return {
        **flow_context,
        "alert_id": alert.get("id"),
        "packet_id": alert.get("packet_id"),
        "linked_packet_id": linked_packet.get("id") if linked_packet else None,
        "linked_packet": linked_packet,
        "linked_packet_summary": _packet_preview(linked_packet) if linked_packet else None,
        "related_packets": related_packets,
        "related_alerts": related_alerts,
        "same_remote_packets": same_remote_packets,
        "same_remote_alerts": same_remote_alerts,
        "alert_correlation": alert_correlation,
        "root_cause_groups": root_cause_groups,
        "source": source,
    }


@dataclass(frozen=True)
class PacketListQuery:
    src: str = ""
    dst: str = ""
    proto: str = ""
    process: str = ""
    pid: str = ""
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
            process=str(raw.get("process") or "").strip(),
            pid=str(raw.get("pid") or "").strip(),
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
    process: str = ""
    pid: str = ""
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
            process=str(raw.get("process") or "").strip(),
            pid=str(raw.get("pid") or "").strip(),
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

    def get_packet_flow_context(self, packet_id: str) -> dict[str, Any] | None:
        ...

    def get_alert_detail(self, alert_id: str) -> dict[str, Any] | None:
        ...

    def get_alert_context(self, alert_id: str) -> dict[str, Any] | None:
        ...

    async def alist_packets(self, query: PacketListQuery) -> dict[str, Any]:
        ...

    async def alist_alerts(self, query: AlertListQuery) -> dict[str, Any]:
        ...

    async def aget_packet_detail(self, packet_id: str) -> dict[str, Any] | None:
        ...

    async def aget_packet_flow_context(self, packet_id: str) -> dict[str, Any] | None:
        ...

    async def aget_alert_detail(self, alert_id: str) -> dict[str, Any] | None:
        ...

    async def aget_alert_context(self, alert_id: str) -> dict[str, Any] | None:
        ...


class BaseHistoryRepository:
    async def alist_packets(self, query: PacketListQuery) -> dict[str, Any]:
        return await asyncio.to_thread(self.list_packets, query)

    async def alist_alerts(self, query: AlertListQuery) -> dict[str, Any]:
        return await asyncio.to_thread(self.list_alerts, query)

    async def aget_packet_detail(self, packet_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self.get_packet_detail, packet_id)

    async def aget_packet_flow_context(self, packet_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self.get_packet_flow_context, packet_id)

    async def aget_alert_detail(self, alert_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self.get_alert_detail, alert_id)

    async def aget_alert_context(self, alert_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self.get_alert_context, alert_id)


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
            if query.process:
                process_hay = " ".join(
                    [
                        str(row.get("process_name") or ""),
                        str(row.get("parent_process_name") or ""),
                        str(row.get("executable_path") or ""),
                    ]
                ).lower()
                if query.process.lower() not in process_hay:
                    return False
            if query.pid:
                if str(row.get("pid") or "").strip() != query.pid:
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
                        str(row.get("protocol_basis") or ""),
                        str(row.get("protocol_notes") or ""),
                        str(row.get("process_name") or ""),
                        str(row.get("parent_process_name") or ""),
                        str(row.get("executable_path") or ""),
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
            if query.process:
                process_hay = " ".join(
                    [
                        str(row.get("process_name") or ""),
                        str(row.get("parent_process_name") or ""),
                        str(row.get("executable_path") or ""),
                    ]
                ).lower()
                if query.process.lower() not in process_hay:
                    return False
            if query.pid:
                if str(row.get("pid") or "").strip() != query.pid:
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
                        str(row.get("protocol_basis") or ""),
                        str(row.get("protocol_notes") or ""),
                        str(row.get("process_name") or ""),
                        str(row.get("parent_process_name") or ""),
                        str(row.get("executable_path") or ""),
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

    def get_packet_flow_context(self, packet_id: str) -> dict[str, Any] | None:
        packet = self.get_packet_detail(packet_id)
        if packet is None:
            return None
        packet_rows = [dict(row) for row in self._sniffer_service.recent_packets()]
        alert_rows = [dict(row) for row in self._sniffer_service.recent_alerts()]
        return _build_packet_flow_context(packet, packet_rows, alert_rows, source="memory")

    def get_alert_detail(self, alert_id: str) -> dict[str, Any] | None:
        rows = list(self._sniffer_service.recent_alerts())
        for row in rows:
            if str(row.get("id") or "") == str(alert_id):
                return dict(row)
        return None

    def get_alert_context(self, alert_id: str) -> dict[str, Any] | None:
        alert = self.get_alert_detail(alert_id)
        if alert is None:
            return None
        packet_rows = [dict(row) for row in self._sniffer_service.recent_packets()]
        alert_rows = [dict(row) for row in self._sniffer_service.recent_alerts()]
        return _build_alert_investigation_context(alert, packet_rows, alert_rows, source="memory")


class SQLiteHistoryRepository(BaseHistoryRepository):
    def __init__(self, db_path: str = DB_PATH, connect_factory: Callable[[str], sqlite3.Connection] | None = None) -> None:
        self._db_path = db_path
        self._connect_factory = connect_factory or self._default_connect

    @staticmethod
    def _default_connect(db_path: str) -> sqlite3.Connection:
        return sqlite3.connect(db_path)

    @staticmethod
    def _configure_connection(conn: sqlite3.Connection) -> sqlite3.Connection:
        conn.row_factory = sqlite3.Row
        conn.create_function("netbot_is_remote_flow", 3, _sqlite_is_remote_flow)
        return conn

    @staticmethod
    async def _configure_async_connection(conn: aiosqlite.Connection) -> aiosqlite.Connection:
        try:
            conn.row_factory = sqlite3.Row
        except Exception:
            pass
        await conn.create_function("netbot_is_remote_flow", 3, _sqlite_is_remote_flow)
        return conn

    def list_packets(self, query: PacketListQuery) -> dict[str, Any]:
        try:
            conn = self._configure_connection(self._connect_factory(self._db_path))
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("History database is unavailable") from exc
        try:
            where, params = self._build_packet_where(query, self._table_columns(conn, "packets"))
            cur = conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM packets{where}", params)
            total = int(cur.fetchone()[0])
            cur.execute(
                f"SELECT * FROM packets{where} ORDER BY id DESC LIMIT ? OFFSET ?",
                [*params, query.limit, query.offset],
            )
            items = [self._normalize_packet_row(row) for row in cur.fetchall()]
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("Packet history query failed") from exc
        finally:
            conn.close()
        return {"items": items, "total": total, "limit": query.limit, "offset": query.offset, "source": "sqlite"}

    def list_alerts(self, query: AlertListQuery) -> dict[str, Any]:
        try:
            conn = self._configure_connection(self._connect_factory(self._db_path))
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("History database is unavailable") from exc
        try:
            where, params = self._build_alert_where(query, self._table_columns(conn, "alerts"))
            cur = conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM alerts{where}", params)
            total = int(cur.fetchone()[0])
            cur.execute(
                f"SELECT * FROM alerts{where} ORDER BY id DESC LIMIT ? OFFSET ?",
                [*params, query.limit, query.offset],
            )
            items = [self._normalize_alert_row(row) for row in cur.fetchall()]
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("Alert history query failed") from exc
        finally:
            conn.close()
        return {"items": items, "total": total, "limit": query.limit, "offset": query.offset, "source": "sqlite"}

    async def alist_packets(self, query: PacketListQuery) -> dict[str, Any]:
        try:
            async with aiosqlite.connect(self._db_path) as conn:
                await self._configure_async_connection(conn)
                where, params = self._build_packet_where(query, await self._table_columns_async(conn, "packets"))
                total = int(await self._fetch_scalar_async(conn, f"SELECT COUNT(*) FROM packets{where}", params))
                rows = await self._fetch_rows_async(
                    conn,
                    f"SELECT * FROM packets{where} ORDER BY id DESC LIMIT ? OFFSET ?",
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
        try:
            async with aiosqlite.connect(self._db_path) as conn:
                await self._configure_async_connection(conn)
                where, params = self._build_alert_where(query, await self._table_columns_async(conn, "alerts"))
                total = int(await self._fetch_scalar_async(conn, f"SELECT COUNT(*) FROM alerts{where}", params))
                rows = await self._fetch_rows_async(
                    conn,
                    f"SELECT * FROM alerts{where} ORDER BY id DESC LIMIT ? OFFSET ?",
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
                "SELECT * FROM packets WHERE id = ?",
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
                    "SELECT * FROM packets WHERE id = ?",
                    (pid,),
                )
        except aiosqlite.Error as exc:
            raise HistoryRepositoryError("Packet detail query failed") from exc
        return self._normalize_packet_row(row) if row else None

    def get_packet_flow_context(self, packet_id: str) -> dict[str, Any] | None:
        packet = self.get_packet_detail(packet_id)
        if packet is None:
            return None
        packet_identity = _flow_identity(packet)
        try:
            conn = self._configure_connection(self._connect_factory(self._db_path))
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("History database is unavailable") from exc
        try:
            packet_rows = self._fetch_context_packets(conn, packet_identity)
            alert_rows = self._fetch_context_alerts(conn, packet_identity)
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("Packet flow context query failed") from exc
        finally:
            conn.close()
        return _build_packet_flow_context(packet, packet_rows, alert_rows, source="sqlite")

    async def aget_packet_flow_context(self, packet_id: str) -> dict[str, Any] | None:
        packet = await self.aget_packet_detail(packet_id)
        if packet is None:
            return None
        packet_identity = _flow_identity(packet)
        try:
            async with aiosqlite.connect(self._db_path) as conn:
                await self._configure_async_connection(conn)
                packet_rows = await self._fetch_context_packets_async(conn, packet_identity)
                alert_rows = await self._fetch_context_alerts_async(conn, packet_identity)
        except aiosqlite.Error as exc:
            raise HistoryRepositoryError("Packet flow context query failed") from exc
        return _build_packet_flow_context(packet, packet_rows, alert_rows, source="sqlite")

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
                "SELECT * FROM alerts WHERE id = ?",
                (aid,),
            )
            row = cur.fetchone()
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("Alert detail query failed") from exc
        finally:
            conn.close()
        return self._normalize_alert_row(row) if row else None

    def get_alert_context(self, alert_id: str) -> dict[str, Any] | None:
        alert = self.get_alert_detail(alert_id)
        if alert is None:
            return None
        anchor_identity = _flow_identity(alert)
        try:
            conn = self._configure_connection(self._connect_factory(self._db_path))
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("History database is unavailable") from exc
        try:
            packet_rows = self._fetch_context_packets(conn, anchor_identity)
            alert_rows = self._fetch_context_alerts(conn, anchor_identity)
        except sqlite3.Error as exc:
            raise HistoryRepositoryError("Alert context query failed") from exc
        finally:
            conn.close()
        return _build_alert_investigation_context(alert, packet_rows, alert_rows, source="sqlite")

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
                    "SELECT * FROM alerts WHERE id = ?",
                    (aid,),
                )
        except aiosqlite.Error as exc:
            raise HistoryRepositoryError("Alert detail query failed") from exc
        return self._normalize_alert_row(row) if row else None

    async def aget_alert_context(self, alert_id: str) -> dict[str, Any] | None:
        alert = await self.aget_alert_detail(alert_id)
        if alert is None:
            return None
        anchor_identity = _flow_identity(alert)
        try:
            async with aiosqlite.connect(self._db_path) as conn:
                await self._configure_async_connection(conn)
                packet_rows = await self._fetch_context_packets_async(conn, anchor_identity)
                alert_rows = await self._fetch_context_alerts_async(conn, anchor_identity)
        except aiosqlite.Error as exc:
            raise HistoryRepositoryError("Alert context query failed") from exc
        return _build_alert_investigation_context(alert, packet_rows, alert_rows, source="sqlite")

    @staticmethod
    def _build_packet_where(query: PacketListQuery, available_columns: set[str] | None = None) -> tuple[str, list[Any]]:
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
        if query.process:
            process_columns = [column for column in ("process_name", "parent_process_name", "executable_path") if available_columns is None or column in available_columns]
            if process_columns:
                clauses.append("(" + " OR ".join(f"{column} LIKE ?" for column in process_columns) + ")")
                params.extend([f"%{query.process}%"] * len(process_columns))
            else:
                clauses.append("1 = 0")
        if query.pid:
            if available_columns is not None and "pid" not in available_columns:
                clauses.append("1 = 0")
            else:
                try:
                    clauses.append("pid = ?")
                    params.append(int(query.pid))
                except (TypeError, ValueError):
                    clauses.append("pid = ?")
                    params.append(query.pid)
        if query.text:
            text_columns = [
                column
                for column in (
                    "summary",
                    "org",
                    "country",
                    "remote_ip",
                    "app_protocol",
                    "l7",
                    "dns_qname",
                    "http_host",
                    "http_path",
                    "sni",
                    "process_name",
                    "parent_process_name",
                    "executable_path",
                    "protocol_basis",
                    "protocol_notes",
                )
                if available_columns is None or column in available_columns
            ]
            if text_columns:
                clauses.append("(" + " OR ".join(f"{column} LIKE ?" for column in text_columns) + ")")
                params.extend([f"%{query.text}%"] * len(text_columns))
            else:
                clauses.append("1 = 0")
        if query.only_alerts:
            clauses.append("is_alert = 1")
        if query.only_remote:
            clauses.append(_sqlite_remote_clause())
        return (f" WHERE {' AND '.join(clauses)}" if clauses else "", params)

    @staticmethod
    def _build_alert_where(query: AlertListQuery, available_columns: set[str] | None = None) -> tuple[str, list[Any]]:
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
        if query.process:
            process_columns = [column for column in ("process_name", "parent_process_name", "executable_path") if available_columns is None or column in available_columns]
            if process_columns:
                clauses.append("(" + " OR ".join(f"{column} LIKE ?" for column in process_columns) + ")")
                params.extend([f"%{query.process}%"] * len(process_columns))
            else:
                clauses.append("1 = 0")
        if query.pid:
            if available_columns is not None and "pid" not in available_columns:
                clauses.append("1 = 0")
            else:
                try:
                    clauses.append("pid = ?")
                    params.append(int(query.pid))
                except (TypeError, ValueError):
                    clauses.append("pid = ?")
                    params.append(query.pid)
        if query.text:
            text_columns = [
                column
                for column in (
                    "detail",
                    "attack_type",
                    "remote_ip",
                    "app_protocol",
                    "dns_qname",
                    "http_host",
                    "http_path",
                    "sni",
                    "process_name",
                    "parent_process_name",
                    "executable_path",
                    "protocol_basis",
                    "protocol_notes",
                )
                if available_columns is None or column in available_columns
            ]
            if text_columns:
                clauses.append("(" + " OR ".join(f"{column} LIKE ?" for column in text_columns) + ")")
                params.extend([f"%{query.text}%"] * len(text_columns))
            else:
                clauses.append("1 = 0")
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
    def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
        cur = conn.cursor()
        cur.execute(f"PRAGMA table_info({table})")
        return {str(row[1]) for row in cur.fetchall()}

    @staticmethod
    async def _table_columns_async(conn: aiosqlite.Connection, table: str) -> set[str]:
        rows = await SQLiteHistoryRepository._fetch_rows_async(conn, f"PRAGMA table_info({table})", [])
        return {str(row[1]) for row in rows}

    def _fetch_context_packets(self, conn: sqlite3.Connection, identity: dict[str, Any]) -> list[dict[str, Any]]:
        where, params = _context_where_clause(identity)
        cur = conn.cursor()
        cur.execute(
            f"SELECT * FROM packets WHERE {where} ORDER BY id DESC LIMIT ?",
            (*params, _CONTEXT_PACKET_LIMIT),
        )
        return [self._normalize_packet_row(row) for row in cur.fetchall()]

    async def _fetch_context_packets_async(self, conn: aiosqlite.Connection, identity: dict[str, Any]) -> list[dict[str, Any]]:
        where, params = _context_where_clause(identity)
        rows = await self._fetch_rows_async(
            conn,
            f"SELECT * FROM packets WHERE {where} ORDER BY id DESC LIMIT ?",
            [*params, _CONTEXT_PACKET_LIMIT],
        )
        return [self._normalize_packet_row(row) for row in rows]

    def _fetch_context_alerts(self, conn: sqlite3.Connection, identity: dict[str, Any]) -> list[dict[str, Any]]:
        where, params = _context_where_clause(identity)
        cur = conn.cursor()
        cur.execute(
            f"SELECT * FROM alerts WHERE {where} ORDER BY id DESC LIMIT ?",
            (*params, _CONTEXT_ALERT_LIMIT),
        )
        return [self._normalize_alert_row(row) for row in cur.fetchall()]

    async def _fetch_context_alerts_async(self, conn: aiosqlite.Connection, identity: dict[str, Any]) -> list[dict[str, Any]]:
        where, params = _context_where_clause(identity)
        rows = await self._fetch_rows_async(
            conn,
            f"SELECT * FROM alerts WHERE {where} ORDER BY id DESC LIMIT ?",
            [*params, _CONTEXT_ALERT_LIMIT],
        )
        return [self._normalize_alert_row(row) for row in rows]

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
        if hasattr(row, "keys") or isinstance(row, dict):
            packet = {
                "id": _row_get(row, "id"),
                "capture_id": _row_get(row, "capture_id"),
                "ts": _row_get(row, "ts"),
                "src": _row_get(row, "src"),
                "dst": _row_get(row, "dst"),
                "proto": _row_get(row, "proto"),
                "sport": _row_get(row, "sport"),
                "dport": _row_get(row, "dport"),
                "direction": _row_get(row, "direction"),
                "length": _row_get(row, "length"),
                "country": _row_get(row, "country"),
                "org": _row_get(row, "org"),
                "summary": _row_get(row, "summary"),
                "is_alert": bool(_row_get(row, "is_alert")),
                "remote_ip": _preferred_remote_ip({"remote_ip": _row_get(row, "remote_ip"), "src": _row_get(row, "src"), "dst": _row_get(row, "dst")}),
                "app_protocol": _row_get(row, "app_protocol"),
                "app_category": _row_get(row, "app_category"),
                "app_confidence": _row_get(row, "app_confidence"),
                "protocol_basis": _row_get(row, "protocol_basis"),
                "protocol_notes": _row_get(row, "protocol_notes"),
                "protocol_handshake": _row_get(row, "protocol_handshake"),
                "protocol_unusual_port": _row_get(row, "protocol_unusual_port"),
                "l7": _row_get(row, "l7"),
                "dns_qname": _row_get(row, "dns_qname"),
                "dns_qtype": _row_get(row, "dns_qtype"),
                "dns_rcode": _row_get(row, "dns_rcode"),
                "http_method": _row_get(row, "http_method"),
                "http_status": _row_get(row, "http_status"),
                "http_reason": _row_get(row, "http_reason"),
                "http_host": _row_get(row, "http_host"),
                "http_path": _row_get(row, "http_path"),
                "http_user_agent": _row_get(row, "http_user_agent"),
                "http_content_type": _row_get(row, "http_content_type"),
                "sni": _row_get(row, "sni"),
                "tls_version": _row_get(row, "tls_version"),
                "tls_alpn": _row_get(row, "tls_alpn"),
                "ja3": _row_get(row, "ja3"),
                "ja3_str": _row_get(row, "ja3_str"),
                "ja4": _row_get(row, "ja4"),
                "payload_len": _row_get(row, "payload_len"),
                "payload_hex": _row_get(row, "payload_hex"),
                "payload_ascii": _row_get(row, "payload_ascii"),
                "payload_binary_like": _row_get(row, "payload_binary_like"),
                "payload_entropy": _row_get(row, "payload_entropy"),
                "payload_printable_ratio": _row_get(row, "payload_printable_ratio"),
                "pid": _row_get(row, "pid"),
                "process_name": _row_get(row, "process_name"),
                "parent_pid": _row_get(row, "parent_pid"),
                "parent_process_name": _row_get(row, "parent_process_name"),
                "executable_path": _row_get(row, "executable_path"),
                "attribution_confidence": _row_get(row, "attribution_confidence"),
                "attribution_reason_unavailable": _row_get(row, "attribution_reason_unavailable"),
                "attribution_source": _row_get(row, "attribution_source"),
            }
            return _enrich_protocol_metadata(packet)

        packet = {
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
            "app_protocol": row[13] if len(row) > 13 else None,
            "app_category": row[14] if len(row) > 14 else None,
            "app_confidence": row[15] if len(row) > 15 else None,
            "l7": row[16] if len(row) > 16 else None,
            "dns_qname": row[17] if len(row) > 17 else None,
            "http_host": row[18] if len(row) > 18 else None,
            "http_path": row[19] if len(row) > 19 else None,
            "sni": row[20] if len(row) > 20 else None,
            "tls_version": row[21] if len(row) > 21 else None,
            "pid": row[22] if len(row) > 22 else None,
            "process_name": row[23] if len(row) > 23 else None,
            "parent_pid": row[24] if len(row) > 24 else None,
            "parent_process_name": row[25] if len(row) > 25 else None,
            "executable_path": row[26] if len(row) > 26 else None,
            "attribution_confidence": row[27] if len(row) > 27 else None,
            "attribution_reason_unavailable": row[28] if len(row) > 28 else None,
            "attribution_source": row[29] if len(row) > 29 else None,
        }
        return _enrich_protocol_metadata(packet)

    @staticmethod
    def _normalize_alert_row(row: tuple[Any, ...]) -> dict[str, Any]:
        if hasattr(row, "keys") or isinstance(row, dict):
            alert = {
                "id": _row_get(row, "id"),
                "ts": _row_get(row, "ts"),
                "src": _row_get(row, "src"),
                "dst": _row_get(row, "dst"),
                "proto": _row_get(row, "proto"),
                "sport": _row_get(row, "sport"),
                "dport": _row_get(row, "dport"),
                "direction": _row_get(row, "direction"),
                "attack_type": _row_get(row, "attack_type"),
                "score": _row_get(row, "score"),
                "detail": _row_get(row, "detail"),
                "severity": _row_get(row, "severity"),
                "engine": _row_get(row, "engine"),
                "score_raw": _row_get(row, "score_raw"),
                "incident_id": _row_get(row, "incident_id"),
                "incident_count": _row_get(row, "incident_count"),
                "incident_score": _row_get(row, "incident_score"),
                "packet_id": _row_get(row, "packet_id"),
                "remote_ip": _preferred_remote_ip({"remote_ip": _row_get(row, "remote_ip"), "src": _row_get(row, "src"), "dst": _row_get(row, "dst")}),
                "app_protocol": _row_get(row, "app_protocol"),
                "app_category": _row_get(row, "app_category"),
                "app_confidence": _row_get(row, "app_confidence"),
                "protocol_basis": _row_get(row, "protocol_basis"),
                "protocol_notes": _row_get(row, "protocol_notes"),
                "protocol_handshake": _row_get(row, "protocol_handshake"),
                "protocol_unusual_port": _row_get(row, "protocol_unusual_port"),
                "dns_qname": _row_get(row, "dns_qname"),
                "dns_qtype": _row_get(row, "dns_qtype"),
                "dns_rcode": _row_get(row, "dns_rcode"),
                "http_method": _row_get(row, "http_method"),
                "http_host": _row_get(row, "http_host"),
                "http_path": _row_get(row, "http_path"),
                "http_status": _row_get(row, "http_status"),
                "http_reason": _row_get(row, "http_reason"),
                "http_user_agent": _row_get(row, "http_user_agent"),
                "http_content_type": _row_get(row, "http_content_type"),
                "sni": _row_get(row, "sni"),
                "tls_version": _row_get(row, "tls_version"),
                "tls_alpn": _row_get(row, "tls_alpn"),
                "ja3": _row_get(row, "ja3"),
                "ja3_str": _row_get(row, "ja3_str"),
                "ja4": _row_get(row, "ja4"),
                "payload_len": _row_get(row, "payload_len"),
                "payload_hex": _row_get(row, "payload_hex"),
                "payload_ascii": _row_get(row, "payload_ascii"),
                "payload_binary_like": _row_get(row, "payload_binary_like"),
                "payload_entropy": _row_get(row, "payload_entropy"),
                "payload_printable_ratio": _row_get(row, "payload_printable_ratio"),
                "pid": _row_get(row, "pid"),
                "process_name": _row_get(row, "process_name"),
                "parent_pid": _row_get(row, "parent_pid"),
                "parent_process_name": _row_get(row, "parent_process_name"),
                "executable_path": _row_get(row, "executable_path"),
                "attribution_confidence": _row_get(row, "attribution_confidence"),
                "attribution_reason_unavailable": _row_get(row, "attribution_reason_unavailable"),
                "attribution_source": _row_get(row, "attribution_source"),
            }
            return _enrich_protocol_metadata(alert)

        alert = {
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
            "app_protocol": row[16] if len(row) > 16 else None,
            "app_category": row[17] if len(row) > 17 else None,
            "app_confidence": row[18] if len(row) > 18 else None,
            "dns_qname": row[19] if len(row) > 19 else None,
            "http_host": row[20] if len(row) > 20 else None,
            "http_path": row[21] if len(row) > 21 else None,
            "sni": row[22] if len(row) > 22 else None,
            "pid": row[23] if len(row) > 23 else None,
            "process_name": row[24] if len(row) > 24 else None,
            "parent_pid": row[25] if len(row) > 25 else None,
            "parent_process_name": row[26] if len(row) > 26 else None,
            "executable_path": row[27] if len(row) > 27 else None,
            "attribution_confidence": row[28] if len(row) > 28 else None,
            "attribution_reason_unavailable": row[29] if len(row) > 29 else None,
            "attribution_source": row[30] if len(row) > 30 else None,
        }
        return _enrich_protocol_metadata(alert)
