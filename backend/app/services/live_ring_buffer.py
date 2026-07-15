from __future__ import annotations

import os
import threading
import uuid
from collections import deque
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from backend.app.services.redaction import redact_sensitive_data, redact_sensitive_text

SUPPORTED_CATEGORIES = (
    "packet",
    "flow",
    "alert",
    "incident",
    "expert_info",
    "protocol_metadata",
    "agent_status",
    "ops_event",
)

DEFAULT_CAPACITIES = {
    "packet": 5000,
    "flow": 2000,
    "alert": 1000,
    "incident": 1000,
    "expert_info": 1000,
    "protocol_metadata": 2000,
    "agent_status": 1000,
    "ops_event": 1000,
}

ENV_CAPACITY_NAMES = {
    "packet": "NETBOT_LIVE_RING_PACKET_MAX",
    "flow": "NETBOT_LIVE_RING_FLOW_MAX",
    "alert": "NETBOT_LIVE_RING_ALERT_MAX",
    "incident": "NETBOT_LIVE_RING_INCIDENT_MAX",
    "expert_info": "NETBOT_LIVE_RING_EXPERT_MAX",
    "protocol_metadata": "NETBOT_LIVE_RING_PROTOCOL_MAX",
    "agent_status": "NETBOT_LIVE_RING_AGENT_MAX",
    "ops_event": "NETBOT_LIVE_RING_OPS_MAX",
}

RAW_PAYLOAD_KEYS = {
    "payload_ascii",
    "payload_hex",
    "raw_payload",
    "packet_bytes",
    "pcap",
    "pcap_bytes",
}


def _env_bool(name: str, default: bool) -> bool:
    value = str(os.environ.get(name, str(default))).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if minimum <= value <= maximum else default


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_timestamp(value: str | None = None) -> str:
    if not value:
        return _utc_now().isoformat()
    parsed = _parse_timestamp(value)
    return parsed.isoformat() if parsed else _utc_now().isoformat()


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _safe_payload(value: Any) -> Any:
    redacted = redact_sensitive_data(deepcopy(value))
    if isinstance(redacted, dict):
        return {
            key: "" if str(key).lower() in RAW_PAYLOAD_KEYS else _safe_payload(item)
            for key, item in redacted.items()
        }
    if isinstance(redacted, list):
        return [_safe_payload(item) for item in redacted]
    return redacted


@dataclass(frozen=True)
class LiveRingBufferRecord:
    id: str
    type: str
    timestamp: str
    flow_key: str
    payload: Any
    source: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LiveRingBuffer:
    """Thread-safe, capacity-bounded recent live analysis storage."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        capacities: dict[str, int] | None = None,
        default_query_limit: int = 250,
        max_query_limit: int = 2000,
        ttl_seconds: int = 0,
    ) -> None:
        configured = capacities or DEFAULT_CAPACITIES
        self.enabled = bool(enabled)
        self.capacities = {
            category: max(
                1, int(configured.get(category, DEFAULT_CAPACITIES[category]))
            )
            for category in SUPPORTED_CATEGORIES
        }
        self.max_query_limit = max(1, min(int(max_query_limit), 10_000))
        self.default_query_limit = max(
            1, min(int(default_query_limit), self.max_query_limit)
        )
        self.ttl_seconds = max(0, int(ttl_seconds))
        self._buffers = {category: deque() for category in SUPPORTED_CATEGORIES}
        self._evicted_by_category = {category: 0 for category in SUPPORTED_CATEGORIES}
        self._lock = threading.RLock()
        self._records_added_total = 0
        self._records_evicted_total = 0
        self._records_dropped_total = 0
        self._query_count_total = 0
        self._query_limit_rejected_total = 0
        self._last_added_at = ""
        self._last_evicted_at = ""
        self._last_error = ""

    @classmethod
    def from_env(cls) -> "LiveRingBuffer":
        capacities = {
            category: _env_int(
                ENV_CAPACITY_NAMES[category],
                default,
                minimum=1,
                maximum=1_000_000,
            )
            for category, default in DEFAULT_CAPACITIES.items()
        }
        max_query_limit = _env_int(
            "NETBOT_LIVE_RING_MAX_QUERY_LIMIT", 2000, minimum=1, maximum=10_000
        )
        return cls(
            enabled=_env_bool("NETBOT_LIVE_RING_ENABLED", True),
            capacities=capacities,
            default_query_limit=_env_int(
                "NETBOT_LIVE_RING_DEFAULT_QUERY_LIMIT",
                250,
                minimum=1,
                maximum=max_query_limit,
            ),
            max_query_limit=max_query_limit,
            ttl_seconds=_env_int(
                "NETBOT_LIVE_RING_TTL_SECONDS",
                0,
                minimum=0,
                maximum=31_536_000,
            ),
        )

    def append(
        self,
        category: str,
        payload: Any,
        *,
        flow_key: str = "",
        timestamp: str | None = None,
        source: str = "live_capture",
    ) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        if category not in self._buffers:
            with self._lock:
                self._records_dropped_total += 1
                self._last_error = "UnsupportedCategory"
            return None
        try:
            record = LiveRingBufferRecord(
                id=f"ring-{uuid.uuid4().hex}",
                type=category,
                timestamp=_iso_timestamp(timestamp),
                flow_key=redact_sensitive_text(str(flow_key or ""))[:256],
                payload=_safe_payload(payload),
                source=redact_sensitive_text(str(source or "live_capture"))[:80],
            )
            with self._lock:
                self._prune_expired_locked()
                buffer = self._buffers[category]
                if len(buffer) >= self.capacities[category]:
                    buffer.popleft()
                    self._evicted_by_category[category] += 1
                    self._records_evicted_total += 1
                    self._last_evicted_at = _utc_now().isoformat()
                buffer.append(record)
                self._records_added_total += 1
                self._last_added_at = record.timestamp
            return record.to_dict()
        except Exception as exc:  # pragma: no cover - defensive guard
            with self._lock:
                self._records_dropped_total += 1
                self._last_error = type(exc).__name__
            return None

    def query(
        self,
        category: str = "all",
        *,
        limit: int | None = None,
        flow_key: str = "",
        since: str | None = None,
    ) -> dict[str, Any]:
        requested_limit = (
            self.default_query_limit if limit is None else max(1, int(limit))
        )
        effective_limit = min(requested_limit, self.max_query_limit)
        since_dt = _parse_timestamp(since)
        with self._lock:
            self._query_count_total += 1
            if requested_limit > self.max_query_limit:
                self._query_limit_rejected_total += 1
            self._prune_expired_locked()
            categories = SUPPORTED_CATEGORIES if category == "all" else (category,)
            if any(item not in self._buffers for item in categories):
                raise ValueError("Unsupported live ring buffer category")
            records = [
                record
                for item in categories
                for record in reversed(self._buffers[item])
            ]
            if flow_key:
                records = [record for record in records if record.flow_key == flow_key]
            if since_dt:
                records = [
                    record
                    for record in records
                    if (
                        _parse_timestamp(record.timestamp)
                        or datetime.min.replace(tzinfo=timezone.utc)
                    )
                    >= since_dt
                ]
            if category == "all":
                records.sort(key=lambda record: record.timestamp, reverse=True)
            truncated = (
                len(records) > effective_limit or requested_limit > effective_limit
            )
            items = [record.to_dict() for record in records[:effective_limit]]
        return {
            "items": items,
            "limit": effective_limit,
            "type": category,
            "truncated": truncated,
            "generated_at": _utc_now().isoformat(),
        }

    def snapshot(self, limit_per_category: int | None = None) -> dict[str, Any]:
        limit = limit_per_category or self.default_query_limit
        return {
            category: self.query(category, limit=limit)["items"]
            for category in SUPPORTED_CATEGORIES
        }

    def clear(self) -> None:
        with self._lock:
            for buffer in self._buffers.values():
                buffer.clear()

    def reset(self) -> None:
        with self._lock:
            self.clear()
            self._evicted_by_category = {
                category: 0 for category in SUPPORTED_CATEGORIES
            }
            self._records_added_total = 0
            self._records_evicted_total = 0
            self._records_dropped_total = 0
            self._query_count_total = 0
            self._query_limit_rejected_total = 0
            self._last_added_at = ""
            self._last_evicted_at = ""
            self._last_error = ""

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            self._prune_expired_locked()
            categories = {
                category: {
                    "records": len(buffer),
                    "capacity": self.capacities[category],
                    "utilization_percent": round(
                        len(buffer) / self.capacities[category] * 100.0, 2
                    ),
                    "evicted_total": self._evicted_by_category[category],
                }
                for category, buffer in self._buffers.items()
            }
            total_records = sum(item["records"] for item in categories.values())
            total_capacity = sum(item["capacity"] for item in categories.values())
            utilization = round(total_records / total_capacity * 100.0, 2)
            pressure_reasons = self._pressure_reasons(categories)
            health = (
                "critical"
                if self._last_error
                else ("degraded" if pressure_reasons else "healthy")
            )
            return {
                "enabled": self.enabled,
                "health": health,
                "total_records": total_records,
                "total_capacity": total_capacity,
                "utilization_percent": utilization,
                "records_added_total": self._records_added_total,
                "records_evicted_total": self._records_evicted_total,
                "records_dropped_total": self._records_dropped_total,
                "query_count_total": self._query_count_total,
                "query_limit_rejected_total": self._query_limit_rejected_total,
                "last_added_at": self._last_added_at,
                "last_evicted_at": self._last_evicted_at,
                "last_error": self._last_error,
                "ttl_seconds": self.ttl_seconds,
                "default_query_limit": self.default_query_limit,
                "max_query_limit": self.max_query_limit,
                "categories": categories,
                "pressure_reasons": pressure_reasons,
            }

    def _pressure_reasons(self, categories: dict[str, dict[str, Any]]) -> list[str]:
        reasons: list[str] = []
        if any(item["utilization_percent"] >= 90.0 for item in categories.values()):
            reasons.append("live_ring_high_utilization")
        frequent_evictions = any(
            self._evicted_by_category[category]
            >= max(10, self.capacities[category] // 10)
            for category in SUPPORTED_CATEGORIES
        )
        if frequent_evictions:
            reasons.append("live_ring_frequent_evictions")
        if self._query_limit_rejected_total:
            reasons.append("live_ring_query_limit_rejections")
        if self._last_error:
            reasons.append("live_ring_errors")
        return reasons

    def _prune_expired_locked(self) -> None:
        if self.ttl_seconds <= 0:
            return
        cutoff = _utc_now().timestamp() - self.ttl_seconds
        for category, buffer in self._buffers.items():
            while buffer:
                timestamp = _parse_timestamp(buffer[0].timestamp)
                if timestamp and timestamp.timestamp() >= cutoff:
                    break
                buffer.popleft()
                self._evicted_by_category[category] += 1
                self._records_evicted_total += 1
                self._last_evicted_at = _utc_now().isoformat()


__all__ = [
    "DEFAULT_CAPACITIES",
    "LiveRingBuffer",
    "LiveRingBufferRecord",
    "SUPPORTED_CATEGORIES",
]
