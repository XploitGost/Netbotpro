"""Bounded RAM-only raw capture; one thread owns all native read/stats/close calls."""
from collections import deque
import ctypes
import threading
import time

from core.privacy_redaction import redact_sensitive_text


class CaptureReadError(OSError):
    """A native read failure eligible for adapter re-observation/rebind."""


def raise_reader_failure(status):
    if not status.get('error'):
        return
    detail = status.get('error_detail') or status['error']
    message = 'Raw capture reader failed: ' + str(detail)
    if status.get('error_recoverable') is True:
        raise CaptureReadError(message)
    raise RuntimeError(message)


def native_stats(handle):
    from scapy.libs.winpcapy import pcap_stat, pcap_stats
    result = pcap_stat()
    if pcap_stats(handle, ctypes.byref(result)) != 0:
        raise OSError('pcap_stats unavailable')
    return int(result.ps_recv), int(result.ps_drop), int(result.ps_ifdrop)


class RawBuffer:
    def __init__(self, reader, *, max_bytes=32*1024*1024, max_frames=32768,
                 sampler=native_stats, max_frame_bytes=65535):
        self.reader = reader
        self.max_bytes, self.max_frames = max_bytes, max_frames
        self.max_frame_bytes = max_frame_bytes
        if max_bytes < max_frame_bytes + 128 or max_frames < 1:
            raise ValueError('Raw capture buffer too small')
        self._sampler = sampler
        self._queue = deque()
        self._bytes = self._high_bytes = self._high_frames = self._read = self._waits = 0
        self._stats = None
        self._error = ''
        self._error_detail = ''
        self._error_recoverable = False
        self._finished = False
        self._stop = threading.Event()
        self._sampled = threading.Event()
        self._condition = threading.Condition()
        self.wire_length = None
        # Nonblocking native reads bound Stop even when no packets arrive.
        reader.setnonblock(True)
        self._thread = threading.Thread(target=self._run, name='capture-raw-reader', daemon=True)
        self._thread.start()
        self._sampled.wait(2)

    def __getattr__(self, name):
        return getattr(self.reader, name)

    def _sample(self):
        try:
            result = self._sampler(self.reader.pcap)
        except Exception:
            result = None
        with self._condition:
            self._stats = result
        self._sampled.set()

    def _run(self):
        next_sample = 0
        try:
            while not self._stop.is_set():
                if time.monotonic() >= next_sample:
                    self._sample()
                    next_sample = time.monotonic() + 1
                with self._condition:
                    if len(self._queue) >= self.max_frames or self._bytes + self.max_frame_bytes + 128 > self.max_bytes:
                        self._waits += 1
                        self._condition.wait(.02)
                        continue
                timestamp, data = self.reader.next()
                if data is None:
                    self._stop.wait(.005)
                    continue
                if len(data) > self.max_frame_bytes:
                    raise ValueError('Raw frame exceeds configured snapshot bound')
                with self._condition:
                    self._queue.append((timestamp, data, self.reader.wire_length))
                    self._bytes += len(data) + 128
                    self._read += 1
                    self._high_bytes = max(self._high_bytes, self._bytes)
                    self._high_frames = max(self._high_frames, len(self._queue))
                    self._condition.notify_all()
        except Exception as exc:
            with self._condition:
                self._error = type(exc).__name__
                self._error_detail = redact_sensitive_text(
                    type(exc).__name__ + ': ' + str(exc)
                )[:300]
                self._error_recoverable = isinstance(exc, OSError)
        finally:
            self._sample()
            try:
                self.reader.close()
            finally:
                with self._condition:
                    self._finished = True
                    self._condition.notify_all()

    def cached_stats(self):
        with self._condition:
            return self._stats

    def snapshot(self):
        with self._condition:
            return dict(queued_frames=len(self._queue), queued_bytes=self._bytes,
                        capacity_bytes=self.max_bytes, capacity_frames=self.max_frames,
                        high_water_bytes=self._high_bytes, high_water_frames=self._high_frames,
                        read_total=self._read, backpressure_waits=self._waits,
                        error=self._error, error_detail=self._error_detail,
                        error_recoverable=self._error_recoverable, finished=self._finished)

    def ready(self):
        with self._condition:
            return bool(self._queue) or self._finished

    def next(self):
        with self._condition:
            if self._queue:
                timestamp, data, self.wire_length = self._queue.popleft()
                self._bytes -= len(data) + 128
                self._condition.notify_all()
                return timestamp, data
            if self._error:
                raise_reader_failure({'error': self._error, 'error_detail': self._error_detail,
                                      'error_recoverable': self._error_recoverable})
            return None, None

    __next__ = next

    def stop(self):
        self._stop.set()
        with self._condition:
            self._condition.notify_all()
        self._thread.join()

    def close(self):
        self.stop()


class BufferedSocket:
    _netbot_fast_copy = True
    nonblocking_socket = True

    def __init__(self, original, reader):
        self.original, self.raw_reader = original, reader
        self.closed = False

    def __getattr__(self, name):
        return getattr(self.original, name)

    def recv(self, *args, **kwargs):
        packet = self.original.recv(*args, **kwargs)
        if packet is not None:
            packet.wirelen = self.raw_reader.wire_length
        return packet

    @staticmethod
    def select(sockets, remain=None):
        deadline = time.monotonic() + (remain if remain is not None else .05)
        while True:
            ready = [socket for socket in sockets if socket.raw_reader.ready()]
            if ready or time.monotonic() >= deadline:
                return ready
            time.sleep(min(.005, max(0, deadline-time.monotonic())))

    def close(self):
        if not self.closed:
            self.raw_reader.stop()
            self.closed = True
