"""Opt-in bounded timing samples. Never retains packet values or exception text."""
from collections import deque
from functools import wraps
import threading
import time


class StageProfiler:
    def __init__(self, sample_every=128):
        self.sample_every = max(1, int(sample_every))
        self._lock = threading.Lock()
        self._counts = {}
        self._samples = {}

    def wrap(self, owner, method, label):
        original = getattr(owner, method)
        with self._lock:
            self._counts[label] = 0
            self._samples[label] = deque(maxlen=256)
        @wraps(original)
        def measured(*args, **kwargs):
            with self._lock:
                self._counts[label] += 1
                sample = self._counts[label] % self.sample_every == 0
            if not sample:
                return original(*args, **kwargs)
            started = time.perf_counter()
            try:
                return original(*args, **kwargs)
            finally:
                elapsed = (time.perf_counter()-started)*1000
                with self._lock:
                    self._samples[label].append((time.monotonic(), elapsed))
        setattr(owner, method, measured)

    def stats(self):
        cutoff = time.monotonic()-60
        stages = {}
        with self._lock:
            for label, samples in self._samples.items():
                values = sorted(ms for timestamp, ms in samples if timestamp >= cutoff)
                stages[label] = dict(seen_calls=self._counts[label], samples=len(values),
                    p50_ms=round(values[len(values)//2], 3) if values else 0,
                    p95_ms=round(values[min(len(values)-1, int(len(values)*.95))], 3) if values else 0,
                    max_ms=round(max(values), 3) if values else 0)
        return dict(enabled=True, sample_every=self.sample_every, window_seconds=60,
                    timings='inclusive_wall_clock', stages=stages)
