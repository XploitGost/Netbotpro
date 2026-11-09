from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Callable


class EndpointRiskStats:
    """Windowed detector events, independent of alert/incident list pagination."""

    SEVERITIES = ("info", "low", "medium", "high", "critical")

    def __init__(self, *, clock: Callable[[], float] = time.time,
                 window_sec: int = 1440, bucket_sec: int = 5,
                 max_endpoints: int = 4096, max_ids: int = 50000) -> None:
        self.clock = clock
        self.window_sec = window_sec
        self.bucket_sec = bucket_sec
        self.max_endpoints = max_endpoints
        self.max_ids = max_ids
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self.started_at = self.clock()
            self._rows: dict[str, dict[int, list[int]]] = {}
            self._seen: OrderedDict[str, float] = OrderedDict()
            self._last_cleanup = 0.0
            self._endpoint_overflow = 0
            self._dedup_overflow = 0

    def _cleanup(self, now: float) -> None:
        if now - self._last_cleanup < self.bucket_sec:
            return
        cutoff = int((now - self.window_sec) // self.bucket_sec)
        for ip, buckets in list(self._rows.items()):
            for key in list(buckets):
                if key < cutoff:
                    del buckets[key]
            if not buckets:
                del self._rows[ip]
        while self._seen and next(iter(self._seen.values())) < now - self.window_sec:
            self._seen.popitem(last=False)
        self._last_cleanup = now

    def observe(self, alerts: list[dict[str, Any]]) -> None:
        if not alerts:
            return
        with self._lock:
            now = self.clock()
            self._cleanup(now)
            bucket = int(now // self.bucket_sec)
            for alert in alerts:
                identifier = str(alert.get("id") or "")
                if identifier and identifier in self._seen:
                    continue
                if identifier:
                    self._seen[identifier] = now
                    while len(self._seen) > self.max_ids:
                        self._seen.popitem(last=False)
                        self._dedup_overflow += 1
                severity = str(alert.get("severity") or "low").lower()
                rank = self.SEVERITIES.index(severity) if severity in self.SEVERITIES else 1
                # One detection contributes once to each participating endpoint.
                for ip in {str(alert.get(key) or "") for key in ("src", "dst")} - {""}:
                    if ip not in self._rows and len(self._rows) >= self.max_endpoints:
                        self._endpoint_overflow += 1
                        continue
                    counts = self._rows.setdefault(ip, {}).setdefault(bucket, [0] * 5)
                    counts[rank] += 1

    def snapshot(self, *, limit: int = 8) -> dict[str, Any]:
        with self._lock:
            now = self.clock()
            self._cleanup(now)
            current = int(now // self.bucket_sec)
            trend_keys = list(range(current - 5, current))
            rows = []
            for ip, buckets in self._rows.items():
                totals = [sum(counts[rank] for counts in buckets.values()) for rank in range(5)]
                rank = max(index for index, count in enumerate(totals) if count)
                samples = [None if key * self.bucket_sec < self.started_at else
                           sum(buckets.get(key, [0] * 5)) for key in trend_keys]
                rows.append({"ip": ip, "count": sum(totals),
                             "risk": self.SEVERITIES[rank], "trend": samples})
            rows.sort(key=lambda row: (-self.SEVERITIES.index(row["risk"]), -row["count"], row["ip"]))
            return {"items": rows[:max(1, min(limit, 100))], "total_endpoints": len(rows),
                    "window_seconds": self.window_sec, "bucket_seconds": self.bucket_sec,
                    "started_at": self.started_at, "generated_at": now,
                    "scope": "detector_events", "trend_start": trend_keys[0] * self.bucket_sec,
                    "endpoint_overflow": self._endpoint_overflow,
                    "dedup_overflow": self._dedup_overflow,
                    "coverage_complete": not (self._endpoint_overflow or self._dedup_overflow)}
