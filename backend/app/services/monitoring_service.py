from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int(value: Any) -> int:
    return int(_number(value, 0.0))


def _sum_history_metric(history: dict[str, Any], key: str) -> int:
    return sum(
        _int(values.get(key)) for values in history.values() if isinstance(values, dict)
    )


def _max_history_metric(history: dict[str, Any], key: str) -> float:
    values = [
        _number(item.get(key)) for item in history.values() if isinstance(item, dict)
    ]
    return max(values, default=0.0)


def _packet_queue_pressure_reasons(
    *,
    max_size: int,
    current_depth: int,
    utilization_percent: float,
    high_water_mark: int,
    dropped_total: int,
    worker_alive: bool,
) -> list[str]:
    pressure_reasons: list[str] = []
    if utilization_percent >= 80.0 or (
        max_size and current_depth >= max(1, int(max_size * 0.8))
    ):
        pressure_reasons.append("packet_queue_backlog")
    if max_size and high_water_mark >= max(1, int(max_size * 0.9)):
        pressure_reasons.append("packet_queue_high_water")
    if dropped_total:
        pressure_reasons.append("packet_queue_dropped_packets")
    if not worker_alive:
        pressure_reasons.append("packet_queue_worker_stopped")
    return pressure_reasons


def _packet_queue_health(
    *,
    dropped_total: int,
    worker_alive: bool,
    pressure_reasons: list[str],
) -> str:
    if not worker_alive or dropped_total >= 100:
        return "critical"
    if pressure_reasons:
        return "degraded"
    return "healthy"


def _safe_packet_queue_drop_reason(value: Any) -> str:
    reason = str(value or "")
    if reason in {
        "queue_full_drop_newest",
        "queue_full_drop_oldest",
        "queue_full_after_drop_oldest",
    }:
        return reason
    return ""


def _safe_websocket_drop_reason(value: Any) -> str:
    reason = str(value or "")
    if reason in {
        "client_queue_full_coalesce",
        "client_queue_full_drop_oldest",
        "client_queue_full_drop_newest",
        "client_queue_full_after_policy",
        "client_queue_full_after_drop_oldest",
    }:
        return reason
    return ""


def _safe_persistence_error(value: Any) -> str:
    error_type = str(value or "")
    if error_type and len(error_type) <= 80 and error_type.replace("_", "").isalnum():
        return error_type
    return ""


def _safe_persistence_drop_reason(value: Any) -> str:
    reason = str(value or "")
    if reason in {
        "queue_full_drop_oldest",
        "queue_full_drop_newest",
        "queue_full_reject_new",
    }:
        return reason
    return ""


def _safe_persistence_reasons(value: Any) -> list[str]:
    return [
        reason
        for item in (value if isinstance(value, list) else [])
        if (reason := str(item)).startswith("persistence_")
        and len(reason) <= 80
        and reason.replace("_", "").isalnum()
    ]


def build_monitoring_metrics(
    *,
    sniffer_state: dict[str, Any],
    observability: dict[str, Any],
    flow_summary: dict[str, Any],
) -> dict[str, Any]:
    """Build a compact operational snapshot for monitoring and benchmarks."""

    event_bus = dict(observability.get("event_bus") or {})
    packet_queue = dict(observability.get("packet_queue") or {})
    event_aggregator = dict(observability.get("event_aggregator") or {})
    websocket = dict(observability.get("websocket") or {})
    persistence = dict(observability.get("persistence") or {})
    history = dict(observability.get("history") or {})
    auto_block = dict(observability.get("auto_block") or {})

    packet_queue_size = _int(
        packet_queue.get("current_depth") or packet_queue.get("queue_size")
    )
    packet_queue_max_size = _int(packet_queue.get("max_size"))
    packet_queue_utilization = _number(packet_queue.get("utilization_percent"))
    packet_queue_high_water = _int(
        packet_queue.get("high_water_mark") or packet_queue.get("queue_high_water_mark")
    )
    packet_queue_drops = _int(
        packet_queue.get("dropped_total") or packet_queue.get("dropped_packets")
    )
    packet_queue_worker_alive = bool(packet_queue.get("worker_alive", True))
    queue_size = _int(
        persistence.get("persistence_queue_depth")
        or persistence.get("queue_depth")
        or persistence.get("queue_size")
    )
    persistence_max_size = _int(
        persistence.get("persistence_queue_max")
        or persistence.get("queue_max")
        or persistence.get("max_size")
        or 5000
    )
    persistence_utilization = _number(
        persistence.get("persistence_utilization_percent")
        or persistence.get("queue_utilization_percent")
        or persistence.get("utilization_percent")
    )
    queue_high_water = _int(
        persistence.get("high_water_mark") or persistence.get("queue_high_water_mark")
    )
    dropped_writes = _int(
        persistence.get("persistence_events_dropped_total")
        or persistence.get("events_dropped_total")
        or persistence.get("dropped_writes")
    )
    failed_writes = _int(
        persistence.get("persistence_events_failed_total")
        or persistence.get("events_failed_total")
        or persistence.get("failed_writes")
    )
    flush_errors = _int(persistence.get("flush_errors"))
    persistence_worker_alive = bool(persistence.get("worker_alive", True))
    flow_persistence = dict(persistence.get("flows") or {})
    dropped_messages = _int(event_bus.get("dropped_messages"))
    websocket_slow_clients = _int(
        websocket.get("slow_clients") or websocket.get("websocket_slow_clients")
    )
    websocket_drops = _int(
        websocket.get("dropped_for_slow_client_total")
        or websocket.get("websocket_events_dropped")
    ) + _int(event_aggregator.get("events_dropped_total"))
    websocket_coalesced = _int(websocket.get("coalesced_for_slow_client_total")) + _int(
        event_aggregator.get("events_coalesced_total")
    )
    websocket_latency = _number(
        websocket.get("send_latency_ms_p95")
        or websocket.get("websocket_send_latency_ms")
    )
    websocket_latency_avg = _number(
        websocket.get("send_latency_ms_avg")
        or websocket.get("websocket_send_latency_ms_avg")
    )
    websocket_send_errors = _int(websocket.get("send_errors_total"))
    history_errors = _sum_history_metric(history, "errors")
    history_slow_calls = _sum_history_metric(history, "slow_calls")
    history_max_ms = _max_history_metric(history, "max_ms")

    packet_queue_pressure_reasons = _packet_queue_pressure_reasons(
        max_size=packet_queue_max_size,
        current_depth=packet_queue_size,
        utilization_percent=packet_queue_utilization,
        high_water_mark=packet_queue_high_water,
        dropped_total=packet_queue_drops,
        worker_alive=packet_queue_worker_alive,
    )

    persistence_reasons = _safe_persistence_reasons(
        persistence.get("persistence_pressure_reasons")
        or persistence.get("pressure_reasons")
        or []
    )
    pressure_reasons: list[str] = list(packet_queue_pressure_reasons)
    pressure_reasons.extend(
        reason for reason in persistence_reasons if reason not in pressure_reasons
    )
    if persistence_utilization >= 80.0 or queue_size >= max(
        1, int(persistence_max_size * 0.8)
    ):
        pressure_reasons.append("persistence_queue_backlog")
    if queue_high_water >= max(1, int(persistence_max_size * 0.9)):
        pressure_reasons.append("persistence_queue_high_water")
    if dropped_writes:
        pressure_reasons.append("persistence_dropped_writes")
    if flush_errors:
        pressure_reasons.append("persistence_flush_errors")
    if failed_writes:
        pressure_reasons.append("persistence_failed_writes")
    if not persistence_worker_alive:
        pressure_reasons.append("persistence_worker_stopped")
    if _int(flow_persistence.get("dropped_total")):
        pressure_reasons.append("flow_persistence_dropped_writes")
    if _int(flow_persistence.get("failed_total")):
        pressure_reasons.append("flow_persistence_failed_writes")
    if dropped_messages:
        pressure_reasons.append("websocket_dropped_messages")
    if websocket_slow_clients:
        pressure_reasons.append("websocket_slow_clients")
    if websocket_drops:
        pressure_reasons.append("websocket_events_dropped")
    if websocket_coalesced:
        pressure_reasons.append("websocket_events_coalesced")
    if websocket_latency >= 250.0:
        pressure_reasons.append("websocket_send_latency")
    if websocket_send_errors:
        pressure_reasons.append("websocket_send_errors")
    if history_errors:
        pressure_reasons.append("history_query_errors")
    if history_slow_calls or history_max_ms >= 250.0:
        pressure_reasons.append("history_query_latency")

    health = "healthy"
    if pressure_reasons:
        health = "degraded"
    if (
        not packet_queue_worker_alive
        or packet_queue_drops >= 100
        or dropped_writes >= 100
        or flush_errors >= 3
        or failed_writes >= 100
        or not persistence_worker_alive
        or queue_size >= max(1, int(persistence_max_size * 0.95))
        or persistence.get("persistence_health") == "critical"
        or persistence.get("health") == "critical"
        or websocket_send_errors >= 3
        or websocket_drops >= _int(event_aggregator.get("client_queue_max") or 1000)
    ):
        health = "critical"

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "health": health,
        "pressure_reasons": pressure_reasons,
        "capture": {
            "running": bool(sniffer_state.get("running")),
            "interface": sniffer_state.get("iface") or "default",
            "total_packets": _int(
                sniffer_state.get("total_packets") or sniffer_state.get("packet_count")
            ),
            "total_alerts": _int(
                sniffer_state.get("total_alerts") or sniffer_state.get("alert_count")
            ),
        },
        "event_bus": {
            "subscribers": _int(event_bus.get("subscribers")),
            "published_messages": _int(event_bus.get("published_messages")),
            "dropped_messages": dropped_messages,
            "dropped_subscribers": _int(event_bus.get("dropped_subscribers")),
        },
        "event_aggregator": {
            "enabled": bool(event_aggregator.get("enabled", True)),
            "packet_batch_ms": _int(event_aggregator.get("packet_batch_ms") or 500),
            "packet_batch_max": _int(event_aggregator.get("packet_batch_max") or 250),
            "alert_batch_ms": _int(event_aggregator.get("alert_batch_ms") or 500),
            "alert_batch_max": _int(event_aggregator.get("alert_batch_max") or 100),
            "flow_batch_ms": _int(event_aggregator.get("flow_batch_ms") or 1000),
            "flow_batch_max": _int(event_aggregator.get("flow_batch_max") or 200),
            "summary_batch_ms": _int(event_aggregator.get("summary_batch_ms") or 1000),
            "agent_batch_ms": _int(event_aggregator.get("agent_batch_ms") or 5000),
            "pending_packet_events": _int(
                event_aggregator.get("pending_packet_events")
            ),
            "pending_alert_events": _int(event_aggregator.get("pending_alert_events")),
            "pending_flow_events": _int(event_aggregator.get("pending_flow_events")),
            "batches_sent_total": _int(event_aggregator.get("batches_sent_total")),
            "events_received_total": _int(
                event_aggregator.get("events_received_total")
            ),
            "events_sent_total": _int(event_aggregator.get("events_sent_total")),
            "events_coalesced_total": _int(
                event_aggregator.get("events_coalesced_total")
            ),
            "events_dropped_total": _int(event_aggregator.get("events_dropped_total")),
            "websocket_batch_size_avg": _number(
                event_aggregator.get("websocket_batch_size_avg")
            ),
            "last_batch_at": event_aggregator.get("last_batch_at") or "",
            "last_drop_reason": _safe_websocket_drop_reason(
                event_aggregator.get("last_drop_reason")
            ),
            "health": event_aggregator.get("health") or "healthy",
            "pressure_reasons": list(event_aggregator.get("pressure_reasons") or []),
        },
        "websocket": {
            "clients": _int(
                websocket.get("clients") or websocket.get("websocket_clients")
            ),
            "websocket_clients": _int(
                websocket.get("clients") or websocket.get("websocket_clients")
            ),
            "slow_clients": websocket_slow_clients,
            "websocket_slow_clients": websocket_slow_clients,
            "client_queue_max": _int(
                websocket.get("client_queue_max")
                or event_aggregator.get("client_queue_max")
                or 1000
            ),
            "client_queue_depth_max": _int(
                websocket.get("client_queue_depth_max")
                or websocket.get("websocket_client_queue_depth")
            ),
            "websocket_client_queue_depth": _int(
                websocket.get("client_queue_depth_max")
                or websocket.get("websocket_client_queue_depth")
            ),
            "send_latency_ms_avg": websocket_latency_avg,
            "websocket_send_latency_ms_avg": websocket_latency_avg,
            "send_latency_ms_p50": _number(websocket.get("send_latency_ms_p50")),
            "send_latency_ms_p95": websocket_latency,
            "websocket_send_latency_ms": websocket_latency,
            "send_errors_total": websocket_send_errors,
            "dropped_for_slow_client_total": _int(
                websocket.get("dropped_for_slow_client_total")
            ),
            "coalesced_for_slow_client_total": _int(
                websocket.get("coalesced_for_slow_client_total")
            ),
            "last_drop_reason": _safe_websocket_drop_reason(
                websocket.get("last_drop_reason")
            ),
            "websocket_last_drop_reason": _safe_websocket_drop_reason(
                websocket.get("websocket_last_drop_reason")
                or websocket.get("last_drop_reason")
            ),
            "health": websocket.get("health") or "healthy",
            "pressure_reasons": list(websocket.get("pressure_reasons") or []),
        },
        "packet_queue": {
            "enabled": bool(packet_queue.get("enabled", True)),
            "max_size": packet_queue_max_size,
            "current_depth": packet_queue_size,
            "queue_size": packet_queue_size,
            "utilization_percent": packet_queue_utilization,
            "accepted_total": _int(
                packet_queue.get("accepted_total")
                or packet_queue.get("accepted_packets")
            ),
            "accepted_packets": _int(
                packet_queue.get("accepted_total")
                or packet_queue.get("accepted_packets")
            ),
            "dropped_total": packet_queue_drops,
            "dropped_packets": packet_queue_drops,
            "dropped_oldest_total": _int(
                packet_queue.get("dropped_oldest_total")
                or packet_queue.get("dropped_oldest")
            ),
            "dropped_newest_total": _int(
                packet_queue.get("dropped_newest_total")
                or packet_queue.get("dropped_newest")
            ),
            "queue_high_water_mark": packet_queue_high_water,
            "high_water_mark": packet_queue_high_water,
            "dropped_oldest": _int(
                packet_queue.get("dropped_oldest_total")
                or packet_queue.get("dropped_oldest")
            ),
            "dropped_newest": _int(
                packet_queue.get("dropped_newest_total")
                or packet_queue.get("dropped_newest")
            ),
            "overflow_policy": packet_queue.get("overflow_policy") or "drop_oldest",
            "worker_alive": packet_queue_worker_alive,
            "last_drop_reason": _safe_packet_queue_drop_reason(
                packet_queue.get("last_drop_reason")
            ),
            "health": _packet_queue_health(
                dropped_total=packet_queue_drops,
                worker_alive=packet_queue_worker_alive,
                pressure_reasons=packet_queue_pressure_reasons,
            ),
            "pressure_reasons": packet_queue_pressure_reasons,
        },
        "persistence": {
            "enabled": bool(
                persistence.get("persistence_enabled", persistence.get("enabled"))
            ),
            "queue_depth": queue_size,
            "queue_max": persistence_max_size,
            "utilization_percent": persistence_utilization,
            "batches_written_total": _int(
                persistence.get("persistence_batches_written_total")
                or persistence.get("batches_written_total")
                or persistence.get("flush_batches")
            ),
            "events_received_total": _int(
                persistence.get("persistence_events_received_total")
                or persistence.get("events_received_total")
                or persistence.get("accepted_writes")
            ),
            "events_written_total": _int(
                persistence.get("persistence_events_written_total")
                or persistence.get("events_written_total")
            ),
            "events_dropped_total": dropped_writes,
            "events_failed_total": failed_writes,
            "retry_total": _int(
                persistence.get("persistence_retry_total")
                or persistence.get("retry_total")
                or persistence.get("flush_retries")
            ),
            "last_flush_at": persistence.get("persistence_last_flush_at")
            or persistence.get("last_flush_at")
            or "",
            "last_error": _safe_persistence_error(
                persistence.get("persistence_last_error")
                or persistence.get("last_error")
            ),
            "last_drop_reason": _safe_persistence_drop_reason(
                persistence.get("persistence_last_drop_reason")
                or persistence.get("last_drop_reason")
            ),
            "write_latency_ms_avg": _number(
                persistence.get("persistence_write_latency_ms_avg")
                or persistence.get("write_latency_avg_ms")
                or persistence.get("avg_flush_ms")
            ),
            "write_latency_ms_p95": _number(
                persistence.get("persistence_write_latency_ms_p95")
                or persistence.get("write_latency_p95_ms")
                or persistence.get("p95_flush_ms")
            ),
            "backlog_age_ms": _number(
                persistence.get("persistence_backlog_age_ms")
                or persistence.get("backlog_age_ms")
            ),
            "high_water_mark": queue_high_water,
            "overflow_policy": persistence.get("overflow_policy")
            or persistence.get("overload_policy")
            or "drop_oldest",
            "persistence_enabled": bool(
                persistence.get("persistence_enabled", persistence.get("enabled"))
            ),
            "queue_utilization_percent": persistence_utilization,
            "write_latency_avg_ms": _number(
                persistence.get("persistence_write_latency_ms_avg")
                or persistence.get("write_latency_avg_ms")
            ),
            "write_latency_p95_ms": _number(
                persistence.get("persistence_write_latency_ms_p95")
                or persistence.get("write_latency_p95_ms")
            ),
            "max_size": persistence_max_size,
            "current_depth": queue_size,
            "queue_size": queue_size,
            "utilization_percent": persistence_utilization,
            "queue_high_water_mark": queue_high_water,
            "accepted_writes": _int(persistence.get("accepted_writes")),
            "dropped_writes": dropped_writes,
            "failed_writes": failed_writes,
            "failed_batches": _int(persistence.get("failed_batches")),
            "persisted_packets": _int(persistence.get("persisted_packets")),
            "persisted_alerts": _int(persistence.get("persisted_alerts")),
            "avg_flush_ms": _number(persistence.get("avg_flush_ms")),
            "p95_flush_ms": _number(persistence.get("p95_flush_ms")),
            "last_flush_ms": _number(persistence.get("last_flush_ms")),
            "avg_batch_size": _number(persistence.get("avg_batch_size")),
            "last_batch_size": _int(persistence.get("last_batch_size")),
            "flush_batches": _int(persistence.get("flush_batches")),
            "flush_errors": flush_errors,
            "flush_retries": _int(persistence.get("flush_retries")),
            "overload_policy": persistence.get("overload_policy") or "drop_oldest",
            "worker_alive": persistence_worker_alive,
            "health": persistence.get("persistence_health")
            or persistence.get("health")
            or "healthy",
            "pressure_reasons": persistence_reasons,
            "flows": {
                "enabled": bool(flow_persistence.get("enabled")),
                "queue_size": _int(flow_persistence.get("queue_size")),
                "max_size": _int(flow_persistence.get("max_size")),
                "utilization_percent": _number(
                    flow_persistence.get("utilization_percent")
                ),
                "persisted_total": _int(flow_persistence.get("persisted_total")),
                "dropped_total": _int(flow_persistence.get("dropped_total")),
                "failed_total": _int(flow_persistence.get("failed_total")),
                "flush_batches": _int(flow_persistence.get("flush_batches")),
                "avg_flush_ms": _number(flow_persistence.get("avg_flush_ms")),
                "worker_alive": bool(flow_persistence.get("worker_alive", True)),
            },
        },
        "history": {
            "operations": len(history),
            "errors": history_errors,
            "slow_calls": history_slow_calls,
            "max_ms": history_max_ms,
        },
        "flows": {
            "total_flows": _int(flow_summary.get("total_flows")),
            "active_flows": _int(flow_summary.get("active_flows")),
            "external_flows": _int(flow_summary.get("external_flows")),
            "internal_flows": _int(flow_summary.get("internal_flows")),
            "risk_distribution": dict(flow_summary.get("risk_distribution") or {}),
        },
        "detection": dict(auto_block),
    }


__all__ = ["build_monitoring_metrics"]
