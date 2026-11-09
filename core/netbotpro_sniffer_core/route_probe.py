"""Single-flight adapter discovery, outside the packet receive thread."""
import threading


class RouteProbe:
    def __init__(self, observe, *, interval=2.0):
        self._observe = observe
        self._interval = max(.01, interval)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._result = None
        self._thread = threading.Thread(target=self._run, name='capture-route-probe', daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.wait(self._interval):
            result = self._observe()
            with self._lock:
                if not self._stop.is_set():
                    self._result = result

    def take(self):
        with self._lock:
            result, self._result = self._result, None
            return result

    def close(self):
        self._stop.set()
        self._thread.join(timeout=.2)
