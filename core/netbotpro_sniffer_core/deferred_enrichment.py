"""Optional lookups never perform network or socket scans on the capture thread."""
from collections import OrderedDict
import queue
import threading
import time


def detached(value):
    return dict(value) if isinstance(value, dict) else value


class DeferredLookup:
    def __init__(self, resolver, fallback, *, ttl=300, capacity=4096, queue_max=128,
                 clock=time.monotonic, enabled=True):
        self._resolver, self._fallback, self._clock = resolver, fallback, clock
        self._ttl, self._capacity = max(.1, ttl), max(1, capacity)
        self._cache = OrderedDict()
        self._pending = set()
        self._queue = queue.Queue(maxsize=max(1, queue_max))
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._hits = self._scheduled = self._rejected = self._errors = 0
        self.enabled = enabled

    def lookup(self, key):
        if not self.enabled:
            return detached(self._fallback)
        now = self._clock()
        with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                if cached[0] > now:
                    self._cache.move_to_end(key)
                    self._hits += 1
                    return detached(cached[1])
                del self._cache[key]
            if not self._stop.is_set() and key not in self._pending:
                try:
                    self._queue.put_nowait(key)
                except queue.Full:
                    self._rejected += 1
                else:
                    self._pending.add(key)
                    self._scheduled += 1
                    if self._thread is None:
                        self._thread = threading.Thread(target=self._run,
                            name='capture-optional-lookup', daemon=True)
                        self._thread.start()
        return detached(self._fallback)

    def _run(self):
        while not self._stop.is_set():
            try:
                key = self._queue.get(timeout=.1)
            except queue.Empty:
                continue
            if self._stop.is_set():
                self._queue.task_done()
                return
            try:
                try:
                    result = self._resolver(key)
                except Exception:
                    result = detached(self._fallback)
                    with self._lock:
                        self._errors += 1
                with self._lock:
                    if not self._stop.is_set():
                        self._cache[key] = (self._clock() + self._ttl, detached(result))
                        self._cache.move_to_end(key)
                        while len(self._cache) > self._capacity:
                            self._cache.popitem(last=False)
                    self._pending.discard(key)
            finally:
                self._queue.task_done()

    def stats(self):
        with self._lock:
            return dict(enabled=self.enabled, cache_entries=len(self._cache), cache_capacity=self._capacity,
                        requests_pending=len(self._pending), queue_depth=self._queue.qsize(),
                        queue_capacity=self._queue.maxsize, cache_hits=self._hits,
                        scheduled=self._scheduled, optional_requests_rejected=self._rejected,
                        lookup_errors=self._errors)

    def close(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(.2)
        with self._lock:
            self._cache.clear()
            self._pending.clear()
            while True:
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except queue.Empty:
                    break


class DeferredProcessMapper:
    def __init__(self):
        from .providers import DefaultProcessMapper
        provider = DefaultProcessMapper()
        self._lookup = DeferredLookup(lambda key: provider.resolve(*key), {
            'pid': None, 'process_name': None,
            'attribution_confidence': 'unavailable',
            'attribution_source': 'pending',
            'attribution_reason_unavailable': 'Process attribution lookup pending.'},
            ttl=.5, queue_max=512)

    def resolve(self, local_ip, local_port, proto):
        return self._lookup.lookup((local_ip, local_port, proto))

    def close(self):
        self._lookup.close()

    def stats(self):
        return self._lookup.stats()


def default_deferred_provider(name, enabled=True):
    from .providers import DefaultGeoIpProvider, DefaultMacVendorProvider
    if name == '_geoip_provider':
        return DeferredLookup(DefaultGeoIpProvider().lookup, {}, ttl=300, enabled=enabled)
    if name == '_mac_vendor_provider':
        return DeferredLookup(DefaultMacVendorProvider().lookup, None, ttl=3600, enabled=enabled)
    return DeferredProcessMapper()
