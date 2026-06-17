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


def build_monitoring_metrics(
    *,
    sniffer_state: dict[str, Any],
    observability: dict[str, Any],
    flow_summary: dict[str, Any],
) -> dict[str, Any]:
    """Build a compact operational snapshot for monitoring and benchmarks."""

    event_bus = dict(observability.get("event_bus") or {})
    persistence = dict(observability.get("persistence") or {})
    history = dict(observability.get("history") or {})
    auto_block = dict(observability.get("auto_block") or {})

    queue_size = _int(persistence.get("queue_size"))
    queue_high_water = _int(persistence.get("queue_high_water_mark"))
    dropped_writes = _int(persistence.get("dropped_writes"))
    flush_errors = _int(persistence.get("flush_errors"))
    dropped_messages = _int(event_bus.get("dropped_messages"))
    history_errors = _sum_history_metric(history, "errors")
    history_slow_calls = _sum_history_metric(history, "slow_calls")
    history_max_ms = _max_history_metric(history, "max_ms")

    pressure_reasons: list[str] = []
    if queue_size >= 1000:
        pressure_reasons.append("persistence_queue_backlog")
    if queue_high_water >= 2500:
        pressure_reasons.append("persistence_queue_high_water")
    if dropped_writes:
        pressure_reasons.append("persistence_dropped_writes")
    if flush_errors:
        pressure_reasons.append("persistence_flush_errors")
    if dropped_messages:
        pressure_reasons.append("websocket_dropped_messages")
    if history_errors:
        pressure_reasons.append("history_query_errors")
    if history_slow_calls or history_max_ms >= 250.0:
        pressure_reasons.append("history_query_latency")

    health = "healthy"
    if pressure_reasons:
        health = "degraded"
    if dropped_writes >= 100 or flush_errors >= 3 or queue_size >= 4000:
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
        "persistence": {
            "queue_size": queue_size,
            "queue_high_water_mark": queue_high_water,
            "dropped_writes": dropped_writes,
            "persisted_packets": _int(persistence.get("persisted_packets")),
            "persisted_alerts": _int(persistence.get("persisted_alerts")),
            "avg_flush_ms": _number(persistence.get("avg_flush_ms")),
            "last_flush_ms": _number(persistence.get("last_flush_ms")),
            "flush_errors": flush_errors,
            "flush_retries": _int(persistence.get("flush_retries")),
            "overload_policy": persistence.get("overload_policy") or "drop_oldest",
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
