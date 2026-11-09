"""Owned capture sockets and cached statistics; never call pcap on a closed handle."""
import ctypes
import threading
import time
from .raw_buffer import raise_reader_failure


def read_pcap_stats(socket):
    reader = getattr(socket, 'raw_reader', None)
    if reader is not None:
        result = reader.cached_stats()
        if result is None:
            raise OSError('Raw reader statistics unavailable')
        return result
    if getattr(socket, 'closed', False):
        raise ValueError('Capture socket closed')
    handle = getattr(getattr(socket, 'pcap_fd', None), 'pcap', None)
    if not handle:
        raise ValueError('No live pcap handle')
    from scapy.libs.winpcapy import pcap_stat, pcap_stats
    result = pcap_stat()
    if pcap_stats(handle, ctypes.byref(result)) != 0:
        raise OSError('pcap_stats unavailable')
    return int(result.ps_recv), int(result.ps_drop), int(result.ps_ifdrop)


class DriverStats:
    def __init__(self):
        self._lock = threading.Lock()
        self._active = {}
        self._opened = self._samples = self._failed_reads = self._uncovered = 0
        self._totals = [0, 0, 0]
        self._last_sample = None
        self._counter_resets = 0
        self._fast_copy_handles = 0

    def register(self, *, fast_copy=False, buffer_bytes=None):
        with self._lock:
            self._opened += 1
            self._fast_copy_handles += int(fast_copy)
            self._active[self._opened] = dict(previous=(0, 0, 0), sampled=False, failed=False, buffer_bytes=buffer_bytes)
            return self._opened

    def record(self, identifier, values):
        with self._lock:
            entry = self._active[identifier]
            if values is None:
                self._failed_reads += 1
                entry['failed'] = True
                return
            for i, value in enumerate(values):
                previous = entry['previous'][i]
                if value < previous and not (previous >= 0xF0000000 and value < 0x10000000):
                    self._counter_resets += 1
                    self._totals[i] += value
                else:
                    self._totals[i] += (value - previous) % (1 << 32)
            entry.update(previous=tuple(values), sampled=True, failed=False)
            self._samples += 1
            self._last_sample = time.monotonic()

    def retire(self, identifier):
        with self._lock:
            entry = self._active.pop(identifier)
            if not entry['sampled'] or entry['failed']:
                self._uncovered += 1

    def snapshot(self):
        with self._lock:
            available = self._samples > 0
            age = time.monotonic()-self._last_sample if self._last_sample is not None else None
            covered = available and not self._uncovered and not self._counter_resets and all(
                value['sampled'] and not value['failed'] for value in self._active.values()) and (not self._active or age <= 5)
            return dict(available=available, coverage_complete=covered,
                        received_reported=self._totals[0] if available else None,
                        buffer_dropped_reported=self._totals[1] if available else None,
                        interface_dropped_raw=self._totals[2] if available else None,
                        interface_drop_support='unknown',
                        scope='opened_capture_handles_only',
                        handles_opened=self._opened, active_handles=len(self._active),
                        uncovered_closed_handles=self._uncovered,
                        samples=self._samples, failed_reads=self._failed_reads,
                        counter_resets=self._counter_resets,
                        active_kernel_buffer_bytes=sum(value['buffer_bytes'] or 0 for value in self._active.values()),
                        kernel_buffer_configuration_complete=bool(self._active) and all(value['buffer_bytes'] is not None for value in self._active.values()),
                        raw_copy_backend='ctypes' if self._opened and self._fast_copy_handles == self._opened else 'mixed' if self._fast_copy_handles else 'scapy' if self._opened else 'unknown',
                        sample_age_seconds=round(age, 3) if age is not None else None)


def open_capture_socket(device, capture_filter):
    from scapy.data import ETH_P_ALL
    from scapy.interfaces import resolve_iface
    from .pcap_reader import attach_fast_reader
    from .pcap_config import open_configured_socket
    socket = open_configured_socket(device, capture_filter)
    if socket is None:
        socket = resolve_iface(device).l2listen()(iface=device, type=ETH_P_ALL,
            **({'filter': capture_filter} if capture_filter else {}))
    try:
        return attach_fast_reader(socket)
    except BaseException:
        socket.close()
        raise


class PcapBinding:
    def __init__(self, target, capture_filter, tracker, *, factory=open_capture_socket,
                 sampler=read_pcap_stats):
        self.devices = tuple(target if isinstance(target, list) else [target])
        self.capture_filter = capture_filter
        self.tracker, self.sampler = tracker, sampler
        self._sockets = []
        try:
            for device in self.devices:
                socket = factory(device, capture_filter)
                identifier = tracker.register(fast_copy=getattr(socket, '_netbot_fast_copy', False),
                    buffer_bytes=getattr(socket, '_netbot_buffer_bytes', None))
                self._sockets.append((socket, identifier, device))
            self.sample()
        except BaseException:
            self.close()
            raise

    def matches(self, target, capture_filter):
        return self.devices == tuple(target if isinstance(target, list) else [target]) and self.capture_filter == capture_filter

    def sniff_arguments(self):
        return {'opened_socket': {socket: device for socket, _identifier, device in self._sockets}}

    def sample(self):
        for socket, identifier, _device in self._sockets:
            try:
                values = self.sampler(socket)
            except Exception:
                values = None
            self.tracker.record(identifier, values)

    def is_closed(self):
        for socket, _identifier, _device in self._sockets:
            reader = getattr(socket, 'raw_reader', None)
            if reader is not None:
                raise_reader_failure(reader.snapshot())
        return any(getattr(socket, 'closed', False) for socket, _identifier, _device in self._sockets)

    def raw_status(self):
        return [socket.raw_reader.snapshot() for socket, _, _ in self._sockets if getattr(socket, 'raw_reader', None) is not None]

    def drain(self, callback):
        buffered = [socket for socket, _, _ in self._sockets if getattr(socket, 'raw_reader', None) is not None]
        for socket in buffered:
            socket.raw_reader.stop()
        for socket in buffered:
            while socket.raw_reader.snapshot()['queued_frames']:
                packet = socket.recv()
                if packet is not None:
                    callback(packet)

    def close(self):
        self.sample()
        sockets, self._sockets = self._sockets, []
        for socket, identifier, _device in sockets:
            try:
                socket.close()
            except Exception:
                self.tracker.record(identifier, None)
            finally:
                self.tracker.retire(identifier)
