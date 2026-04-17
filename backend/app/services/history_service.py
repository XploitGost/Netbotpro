from __future__ import annotations

from collections import OrderedDict
import threading
import time
from typing import Any

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.repositories import AlertListQuery, HistoryRepositoryError, MemoryHistoryRepository, PacketListQuery, SQLiteHistoryRepository

ensure_project_root_on_path()

from log_manager import DB_PATH, is_persist_enabled  # noqa: E402

_DETAIL_CACHE_MAX_ENTRIES = 256
_LIST_CACHE_MAX_ENTRIES = 48
_DETAIL_CACHE_TTL_SEC = 2.5
_LIST_CACHE_TTL_SEC = 1.0


class HistoryService:
    def __init__(
        self,
        sniffer_service: Any,
        sqlite_repository: SQLiteHistoryRepository | None = None,
        memory_repository: MemoryHistoryRepository | None = None,
    ) -> None:
        self._sniffer_service = sniffer_service
        self._sqlite_repository = sqlite_repository or SQLiteHistoryRepository(db_path=DB_PATH)
        self._memory_repository = memory_repository or MemoryHistoryRepository(sniffer_service)
        self._metrics_lock = threading.Lock()
        self._cache_lock = threading.Lock()
        self._list_cache: "OrderedDict[tuple[str, str, str], tuple[float, dict[str, Any] | None]]" = OrderedDict()
        self._detail_cache: "OrderedDict[tuple[str, str, str], tuple[float, dict[str, Any] | None]]" = OrderedDict()
        self._metrics: dict[str, dict[str, float | int]] = {
            "packets_list": self._blank_metric(),
            "alerts_list": self._blank_metric(),
            "packet_detail": self._blank_metric(),
            "packet_context": self._blank_metric(),
            "alert_detail": self._blank_metric(),
            "alert_context": self._blank_metric(),
        }

    def get_packets(self, query: dict[str, Any]) -> dict[str, Any]:
        packet_query = PacketListQuery.from_raw(query)
        started = time.perf_counter()
        cache_key = self._make_cache_key("packets_list", packet_query)
        cached = self._read_cache(self._list_cache, cache_key, ttl_sec=_LIST_CACHE_TTL_SEC)
        if cached is not None:
            duration_ms = self._record_metric("packets_list", time.perf_counter() - started, failed=False)
            cached["query_ms"] = duration_ms
            cached["observability"] = {"history": self.metrics()}
            return cached
        try:
            result = self._repository().list_packets(packet_query)
        except Exception:
            self._record_metric("packets_list", time.perf_counter() - started, failed=True)
            raise
        duration_ms = self._record_metric("packets_list", time.perf_counter() - started, failed=False)
        self._write_cache(self._list_cache, cache_key, result, max_entries=_LIST_CACHE_MAX_ENTRIES, ttl_sec=_LIST_CACHE_TTL_SEC)
        result["query_ms"] = duration_ms
        result["observability"] = {"history": self.metrics()}
        return result

    def get_alerts(self, query: dict[str, Any]) -> dict[str, Any]:
        alert_query = AlertListQuery.from_raw(query)
        started = time.perf_counter()
        cache_key = self._make_cache_key("alerts_list", alert_query)
        cached = self._read_cache(self._list_cache, cache_key, ttl_sec=_LIST_CACHE_TTL_SEC)
        if cached is not None:
            duration_ms = self._record_metric("alerts_list", time.perf_counter() - started, failed=False)
            cached["query_ms"] = duration_ms
            cached["observability"] = {"history": self.metrics()}
            return cached
        try:
            result = self._repository().list_alerts(alert_query)
        except Exception:
            self._record_metric("alerts_list", time.perf_counter() - started, failed=True)
            raise
        duration_ms = self._record_metric("alerts_list", time.perf_counter() - started, failed=False)
        self._write_cache(self._list_cache, cache_key, result, max_entries=_LIST_CACHE_MAX_ENTRIES, ttl_sec=_LIST_CACHE_TTL_SEC)
        result["query_ms"] = duration_ms
        result["observability"] = {"history": self.metrics()}
        return result

    def get_packet_detail(self, packet_id: str) -> dict[str, Any] | None:
        started = time.perf_counter()
        cache_key = self._make_cache_key("packet_detail", packet_id)
        cached = self._read_cache(self._detail_cache, cache_key, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        if cached is not None:
            self._record_metric("packet_detail", time.perf_counter() - started, failed=False)
            return cached
        try:
            result = self._repository().get_packet_detail(packet_id)
        except Exception:
            self._record_metric("packet_detail", time.perf_counter() - started, failed=True)
            raise
        self._record_metric("packet_detail", time.perf_counter() - started, failed=False)
        self._write_cache(self._detail_cache, cache_key, result, max_entries=_DETAIL_CACHE_MAX_ENTRIES, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        return result

    def get_packet_flow_context(self, packet_id: str) -> dict[str, Any] | None:
        started = time.perf_counter()
        cache_key = self._make_cache_key("packet_context", packet_id)
        cached = self._read_cache(self._detail_cache, cache_key, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        if cached is not None:
            self._record_metric("packet_context", time.perf_counter() - started, failed=False)
            return cached
        try:
            result = self._repository().get_packet_flow_context(packet_id)
        except Exception:
            self._record_metric("packet_context", time.perf_counter() - started, failed=True)
            raise
        self._record_metric("packet_context", time.perf_counter() - started, failed=False)
        self._write_cache(self._detail_cache, cache_key, result, max_entries=_DETAIL_CACHE_MAX_ENTRIES, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        return result

    def get_alert_detail(self, alert_id: str) -> dict[str, Any] | None:
        started = time.perf_counter()
        cache_key = self._make_cache_key("alert_detail", alert_id)
        cached = self._read_cache(self._detail_cache, cache_key, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        if cached is not None:
            self._record_metric("alert_detail", time.perf_counter() - started, failed=False)
            return cached
        try:
            result = self._repository().get_alert_detail(alert_id)
        except Exception:
            self._record_metric("alert_detail", time.perf_counter() - started, failed=True)
            raise
        self._record_metric("alert_detail", time.perf_counter() - started, failed=False)
        self._write_cache(self._detail_cache, cache_key, result, max_entries=_DETAIL_CACHE_MAX_ENTRIES, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        return result

    def get_alert_context(self, alert_id: str) -> dict[str, Any] | None:
        started = time.perf_counter()
        cache_key = self._make_cache_key("alert_context", alert_id)
        cached = self._read_cache(self._detail_cache, cache_key, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        if cached is not None:
            self._record_metric("alert_context", time.perf_counter() - started, failed=False)
            return cached
        try:
            result = self._repository().get_alert_context(alert_id)
        except Exception:
            self._record_metric("alert_context", time.perf_counter() - started, failed=True)
            raise
        self._record_metric("alert_context", time.perf_counter() - started, failed=False)
        self._write_cache(self._detail_cache, cache_key, result, max_entries=_DETAIL_CACHE_MAX_ENTRIES, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        return result

    async def aget_packets(self, query: dict[str, Any]) -> dict[str, Any]:
        packet_query = PacketListQuery.from_raw(query)
        started = time.perf_counter()
        cache_key = self._make_cache_key("packets_list", packet_query)
        cached = self._read_cache(self._list_cache, cache_key, ttl_sec=_LIST_CACHE_TTL_SEC)
        if cached is not None:
            duration_ms = self._record_metric("packets_list", time.perf_counter() - started, failed=False)
            cached["query_ms"] = duration_ms
            cached["observability"] = {"history": self.metrics()}
            return cached
        try:
            result = await self._repository().alist_packets(packet_query)
        except Exception:
            self._record_metric("packets_list", time.perf_counter() - started, failed=True)
            raise
        duration_ms = self._record_metric("packets_list", time.perf_counter() - started, failed=False)
        self._write_cache(self._list_cache, cache_key, result, max_entries=_LIST_CACHE_MAX_ENTRIES, ttl_sec=_LIST_CACHE_TTL_SEC)
        result["query_ms"] = duration_ms
        result["observability"] = {"history": self.metrics()}
        return result

    async def aget_alerts(self, query: dict[str, Any]) -> dict[str, Any]:
        alert_query = AlertListQuery.from_raw(query)
        started = time.perf_counter()
        cache_key = self._make_cache_key("alerts_list", alert_query)
        cached = self._read_cache(self._list_cache, cache_key, ttl_sec=_LIST_CACHE_TTL_SEC)
        if cached is not None:
            duration_ms = self._record_metric("alerts_list", time.perf_counter() - started, failed=False)
            cached["query_ms"] = duration_ms
            cached["observability"] = {"history": self.metrics()}
            return cached
        try:
            result = await self._repository().alist_alerts(alert_query)
        except Exception:
            self._record_metric("alerts_list", time.perf_counter() - started, failed=True)
            raise
        duration_ms = self._record_metric("alerts_list", time.perf_counter() - started, failed=False)
        self._write_cache(self._list_cache, cache_key, result, max_entries=_LIST_CACHE_MAX_ENTRIES, ttl_sec=_LIST_CACHE_TTL_SEC)
        result["query_ms"] = duration_ms
        result["observability"] = {"history": self.metrics()}
        return result

    async def aget_packet_detail(self, packet_id: str) -> dict[str, Any] | None:
        started = time.perf_counter()
        cache_key = self._make_cache_key("packet_detail", packet_id)
        cached = self._read_cache(self._detail_cache, cache_key, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        if cached is not None:
            self._record_metric("packet_detail", time.perf_counter() - started, failed=False)
            return cached
        try:
            result = await self._repository().aget_packet_detail(packet_id)
        except Exception:
            self._record_metric("packet_detail", time.perf_counter() - started, failed=True)
            raise
        self._record_metric("packet_detail", time.perf_counter() - started, failed=False)
        self._write_cache(self._detail_cache, cache_key, result, max_entries=_DETAIL_CACHE_MAX_ENTRIES, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        return result

    async def aget_packet_flow_context(self, packet_id: str) -> dict[str, Any] | None:
        started = time.perf_counter()
        cache_key = self._make_cache_key("packet_context", packet_id)
        cached = self._read_cache(self._detail_cache, cache_key, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        if cached is not None:
            self._record_metric("packet_context", time.perf_counter() - started, failed=False)
            return cached
        try:
            result = await self._repository().aget_packet_flow_context(packet_id)
        except Exception:
            self._record_metric("packet_context", time.perf_counter() - started, failed=True)
            raise
        self._record_metric("packet_context", time.perf_counter() - started, failed=False)
        self._write_cache(self._detail_cache, cache_key, result, max_entries=_DETAIL_CACHE_MAX_ENTRIES, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        return result

    async def aget_alert_detail(self, alert_id: str) -> dict[str, Any] | None:
        started = time.perf_counter()
        cache_key = self._make_cache_key("alert_detail", alert_id)
        cached = self._read_cache(self._detail_cache, cache_key, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        if cached is not None:
            self._record_metric("alert_detail", time.perf_counter() - started, failed=False)
            return cached
        try:
            result = await self._repository().aget_alert_detail(alert_id)
        except Exception:
            self._record_metric("alert_detail", time.perf_counter() - started, failed=True)
            raise
        self._record_metric("alert_detail", time.perf_counter() - started, failed=False)
        self._write_cache(self._detail_cache, cache_key, result, max_entries=_DETAIL_CACHE_MAX_ENTRIES, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        return result

    async def aget_alert_context(self, alert_id: str) -> dict[str, Any] | None:
        started = time.perf_counter()
        cache_key = self._make_cache_key("alert_context", alert_id)
        cached = self._read_cache(self._detail_cache, cache_key, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        if cached is not None:
            self._record_metric("alert_context", time.perf_counter() - started, failed=False)
            return cached
        try:
            result = await self._repository().aget_alert_context(alert_id)
        except Exception:
            self._record_metric("alert_context", time.perf_counter() - started, failed=True)
            raise
        self._record_metric("alert_context", time.perf_counter() - started, failed=False)
        self._write_cache(self._detail_cache, cache_key, result, max_entries=_DETAIL_CACHE_MAX_ENTRIES, ttl_sec=_DETAIL_CACHE_TTL_SEC)
        return result

    def metrics(self) -> dict[str, dict[str, float | int]]:
        with self._metrics_lock:
            return {name: dict(values) for name, values in self._metrics.items()}

    def _repository(self):
        if is_persist_enabled():
            return self._sqlite_repository
        return self._memory_repository

    def _cache_mode(self) -> str:
        return "sqlite" if is_persist_enabled() else "memory"

    def _make_cache_key(self, operation: str, payload: Any) -> tuple[str, str, str]:
        return (self._cache_mode(), operation, repr(payload))

    def _read_cache(
        self,
        cache: "OrderedDict[tuple[str, str, str], tuple[float, dict[str, Any] | None]]",
        key: tuple[str, str, str],
        *,
        ttl_sec: float,
    ) -> dict[str, Any] | None:
        now = time.monotonic()
        with self._cache_lock:
            entry = cache.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if expires_at <= now:
                cache.pop(key, None)
                return None
            cache.move_to_end(key)
        if value is None:
            return None
        return dict(value)

    def _write_cache(
        self,
        cache: "OrderedDict[tuple[str, str, str], tuple[float, dict[str, Any] | None]]",
        key: tuple[str, str, str],
        value: dict[str, Any] | None,
        *,
        max_entries: int,
        ttl_sec: float,
    ) -> None:
        expires_at = time.monotonic() + ttl_sec
        with self._cache_lock:
            cache[key] = (expires_at, dict(value) if value is not None else None)
            cache.move_to_end(key)
            while len(cache) > max_entries:
                cache.popitem(last=False)

    @staticmethod
    def _blank_metric() -> dict[str, float | int]:
        return {
            "calls": 0,
            "errors": 0,
            "last_ms": 0.0,
            "avg_ms": 0.0,
            "max_ms": 0.0,
            "slow_calls": 0,
        }

    def _record_metric(self, name: str, duration_sec: float, failed: bool) -> float:
        duration_ms = round(duration_sec * 1000.0, 2)
        with self._metrics_lock:
            metric = self._metrics[name]
            if failed:
                metric["errors"] = int(metric["errors"]) + 1
                metric["last_ms"] = duration_ms
                metric["max_ms"] = max(float(metric["max_ms"]), duration_ms)
                if duration_ms >= 100.0:
                    metric["slow_calls"] = int(metric["slow_calls"]) + 1
                return duration_ms
            calls = int(metric["calls"]) + 1
            metric["calls"] = calls
            metric["last_ms"] = duration_ms
            metric["avg_ms"] = round(((float(metric["avg_ms"]) * (calls - 1)) + duration_ms) / calls, 2)
            metric["max_ms"] = max(float(metric["max_ms"]), duration_ms)
            if duration_ms >= 100.0:
                metric["slow_calls"] = int(metric["slow_calls"]) + 1
        return duration_ms


__all__ = ["HistoryRepositoryError", "HistoryService"]
