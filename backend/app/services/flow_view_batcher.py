from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Callable, Any


class FlowViewBatcher:
    """Bound optional display work without blocking the packet-analysis owner."""

    def __init__(self, publish: Callable[[dict[str, Any]], None], *, interval=0.25, capacity=1024):
        self._publish = publish
        self._capacity = max(1, int(capacity))
        self._pending = OrderedDict()
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._stop = threading.Event()
        self._received = self._published = self._coalesced = 0
        self._capacity_evictions = 0
        self._last_eviction_at = None
        self._errors = 0
        self._last_error = ''
        self._thread = threading.Thread(target=self._run, args=(interval,), daemon=True, name='netbotpro-flow-views')
        self._thread.start()

    def submit(self, snapshot):
        identifier = str(snapshot['flow_id'])
        with self._lock:
            self._received += 1
            if identifier in self._pending:
                self._coalesced += 1
            elif len(self._pending) >= self._capacity:
                # Only a regenerable ring-buffer view is replaced; analysis and
                # durable flow snapshots have independent delivery paths.
                self._pending.popitem(last=False)
                self._capacity_evictions += 1
                self._last_eviction_at = time.monotonic()
            self._pending[identifier] = snapshot
            self._pending.move_to_end(identifier)

    def flush(self):
        with self._flush_lock:
            with self._lock:
                batch = list(self._pending.items())
            for identifier, snapshot in batch:
                try:
                    self._publish(snapshot)
                except Exception as exc:
                    with self._lock:
                        self._errors += 1
                        self._last_error = type(exc).__name__
                    raise
                with self._lock:
                    if self._pending.get(identifier) is snapshot:
                        del self._pending[identifier]
                    self._published += 1
                    self._last_error = ''

    def clear(self):
        with self._flush_lock, self._lock:
            self._pending.clear()

    def stats(self):
        with self._lock:
            eviction_age = (None if self._last_eviction_at is None else
                            max(0.0, time.monotonic() - self._last_eviction_at))
            reasons = ['flow_view_capacity_evictions'] if eviction_age is not None and eviction_age < 60 else []
            if self._last_error:
                reasons.append('flow_view_publish_error')
            if not self._thread.is_alive() and not self._stop.is_set():
                reasons.append('flow_view_worker_stopped')
            return {'received':self._received, 'published':self._published,
                    'coalesced':self._coalesced, 'pending':len(self._pending),
                    'capacity':self._capacity, 'worker_alive':self._thread.is_alive(),
                    'errors_total':self._errors, 'last_error':self._last_error,
                    'capacity_policy':'evict_oldest_optional_view',
                    'capacity_evictions_total':self._capacity_evictions,
                    'last_capacity_eviction_age_seconds':eviction_age,
                    'pressure_reasons':reasons,
                    'health':'degraded' if reasons else 'healthy'}

    def _run(self, interval):
        while not self._stop.wait(interval):
            try:
                self.flush()
            except Exception:
                # Retain the snapshot for the next attempt; explicit drain propagates failure.
                continue

    def close(self):
        self._stop.set()
        self._thread.join()
        self.flush()
