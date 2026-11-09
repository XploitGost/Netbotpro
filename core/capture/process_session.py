"""Opt-in capture isolation. IPC contains metadata, never a network listener."""
from __future__ import annotations

import multiprocessing as mp
import os
import queue
import threading
import time

from core.capture.batch_delivery import BatchDeliveryError, JournalBatchDelivery

_STATE_FIELDS = ('selected_iface', 'auto_interface', 'route_switches', 'route_warning',
                 'driver_stats', 'capture_callback_errors', 'optional_enrichment', 'capture_profile', 'raw_buffers', 'raw_buffer_pressure')


def _capture_child(output, control, stopping, counters, iface, factory, capacity, journal_path):
    parent = mp.parent_process()
    def watch_parent():
        while True:
            time.sleep(.2)
            if parent is not None and not parent.is_alive():
                # No recipient remains to drain IPC. OS closes capture handles.
                os._exit(70)
    threading.Thread(target=watch_parent, name='capture-parent-watch', daemon=True).start()
    engine = None
    journal = None
    control_lock = threading.Lock()
    def report(message):
        with control_lock:
            try:
                control.send(message)
            except (EOFError, OSError):
                stopping.set()
    pending = []
    writer_failed = threading.Event()
    batch_lock = threading.Lock()
    def flush():
        with batch_lock:
            if pending:
                batch = list(pending)
                pending.clear()
                if journal is not None:
                    try:
                        journal.append(batch)
                        with counters.get_lock():
                            counters[1] += len(batch)
                    except Exception as exc:
                        writer_failed.set()
                        with counters.get_lock():
                            counters[2] += len(batch)
                        report(('error', f'Journal write failed: {type(exc).__name__}'))
                        stopping.set()
                else:
                    output.put_nowait(batch)
    def emit(packet):
        if journal is not None:
            with counters.get_lock():
                counters[0] += 1
                if writer_failed.is_set():
                    counters[2] += 1
                    return
            with batch_lock:
                pending.append(dict(packet))
                full = len(pending) >= 32
            if full:
                flush()
            return
        with counters.get_lock():
            counters[0] += 1
            if counters[3] >= capacity:
                counters[2] += 1
                return
            counters[1] += 1
            counters[3] += 1
        with batch_lock:
            pending.append(dict(packet))
            if len(pending) >= 32:
                output.put_nowait(list(pending))
                pending.clear()
    try:
        if journal_path:
            from core.capture.journal import CaptureJournal
            journal = CaptureJournal(journal_path)
        if factory is None:
            from core.core_sniffer import NetSniffer
            factory = NetSniffer
        engine = factory(emit)
        engine.start(iface=iface)
        report(('ready', engine.selected_iface()))
        previous_state = None
        next_report = 0.0
        while not stopping.wait(.1):
            flush()
            status = getattr(engine, 'capture_status', None)
            if callable(status):
                current = status()
                if not current.get('running'):
                    raise RuntimeError(current.get('capture_error') or 'Capture driver exited')
                state = {key: current[key] for key in _STATE_FIELDS if key in current}
                if state and state != previous_state and time.monotonic() >= next_report:
                    report(('state', state))
                    previous_state = state
                    next_report = time.monotonic() + 1.0
    except BaseException as exc:
        report(('error', f'{type(exc).__name__}: {exc}'))
    finally:
        if engine is not None:
            try:
                engine.stop()
                status = getattr(engine, 'capture_status', None)
                if callable(status):
                    current = status()
                    report(('state', {key: current[key] for key in _STATE_FIELDS if key in current}))
            except BaseException as exc:
                report(('error', f'Stop failed: {type(exc).__name__}: {exc}'))
        # Queue ordering puts the sentinel after every accepted metadata record.
        flush()
        if journal is None:
            output.put(None)
        else:
            journal.close()
        output.close()
        output.join_thread()
        control.close()


class ProcessCaptureSession:
    def __init__(self, callback, *, capacity=8192, factory=None, timeout=10, journal_path=None, prepare_batch=None):
        self._callback = callback
        self._prepare_batch = prepare_batch
        self._capacity = max(1, int(capacity))
        self._factory = factory
        self._journal_path = str(journal_path) if journal_path else None
        self._journal = None
        self._journal_snapshot = {}
        self._timeout = timeout
        self._process = None
        self._reader = None
        self._error = ''
        self._iface = None
        self._started = None
        self._delivered = 0
        self._callback_errors = 0
        self._journal_acknowledged = 0
        self._journal_failure_stage = None
        self._complete = threading.Event()
        self._closed = False
        self._lock = threading.Lock()
        self._control_lock = threading.Lock()
        self._journal_lock = threading.Lock()
        self._route_state = {}
        self._route_observed_at = None
        self._control_stop = threading.Event()
        self._control_reader = None

    def set_batch_preparer(self, callback):
        if self._process is not None:
            raise RuntimeError('Batch preparation must be configured before Start')
        self._prepare_batch = callback

    def start(self, iface=None):
        if self._process is not None:
            raise RuntimeError('Capture session already started')
        context = mp.get_context('spawn')
        if self._journal_path:
            from core.capture.journal import CaptureJournal
            self._journal = CaptureJournal(self._journal_path)
        self._output = context.Queue(self._capacity)
        self._control, child_control = context.Pipe(duplex=False)
        self._stopping = context.Event()
        self._counters = context.Array('q', 4)
        self._process = context.Process(target=_capture_child,
            args=(self._output, child_control, self._stopping, self._counters, iface, self._factory, self._capacity, self._journal_path),
            name='netbotpro-capture', daemon=True)
        self._process.start()
        child_control.close()
        self._reader = threading.Thread(target=self._receive, name='capture-ipc-reader', daemon=True)
        self._reader.start()
        try:
            if not self._control.poll(self._timeout):
                raise RuntimeError('Capture child startup timed out')
            kind, value = self._control.recv()
            if kind != 'ready':
                raise RuntimeError(value)
            self._iface = value or iface
            self._started = time.time()
            self._control_reader = threading.Thread(target=self._monitor_control,
                name='capture-control-reader', daemon=True)
            self._control_reader.start()
        except BaseException:
            self._stopping.set()
            self._process.join(self._timeout)
            if self._process.is_alive():
                self._process.terminate()
                self._process.join(self._timeout)
            self._complete.wait(self._timeout)
            self._close_ipc()
            raise

    def _receive(self):
        try:
            if self._journal is not None:
                self._receive_journal()
                return
            while True:
                try:
                    batch = self._output.get(timeout=.1)
                except queue.Empty:
                    if not self._process.is_alive():
                        with self._lock:
                            self._error = self._error or 'Capture child exited without drain marker'
                        return
                    continue
                if batch is None:
                    return
                for packet in batch:
                    try:
                        self._callback(packet)
                        with self._lock:
                            self._delivered += 1
                    except Exception as exc:
                        with self._lock:
                            self._callback_errors += 1
                            self._error = f'Callback failed: {type(exc).__name__}'
                with self._counters.get_lock():
                    self._counters[3] -= len(batch)
        except Exception as exc:
            with self._lock:
                self._error = f'Capture delivery failed: {type(exc).__name__}'
            self._stopping.set()
        finally:
            self._complete.set()

    def _receive_journal(self):
        delivery = JournalBatchDelivery(self._callback, self._journal.acknowledge,
            prepare=self._prepare_batch, on_completed=self._record_journal_completion)
        while True:
            row = self._journal.first()
            if row is None:
                if not self._process.is_alive():
                    # Producer may have committed after the preceding empty read.
                    row = self._journal.first()
                    if row is None:
                        if not self._stopping.is_set():
                            self._read_errors()
                            with self._lock:
                                self._error = self._error or 'Capture journal producer exited'
                        return
                else:
                    time.sleep(.01)
                    continue
            identifier, packets = row
            try:
                receipt = delivery.deliver(identifier, packets)
                with self._lock:
                    self._journal_acknowledged += receipt.completed_records
            except BatchDeliveryError as exc:
                with self._lock:
                    # Preserve the legacy aggregate; expose the actual stage separately.
                    self._callback_errors += 1
                    self._journal_failure_stage = exc.stage
                    self._error = str(exc)
                self._stopping.set()
                return

    def _record_journal_completion(self):
        # Journal callback returns after analysis/delivery, not durable persistence.
        with self._lock:
            self._delivered += 1

    def stop(self):
        if self._process is None:
            return
        self._stopping.set()
        self._process.join(self._timeout)
        if self._process.is_alive() or not self._complete.wait(self._timeout):
            raise RuntimeError('Capture child or IPC did not drain; retry Stop')
        self._read_errors()
        self._close_ipc()
        if self._error:
            raise RuntimeError(self._error)

    def _close_ipc(self):
        if not self._closed and self._complete.is_set():
            self._control_stop.set()
            if self._control_reader is not None:
                self._control_reader.join(1)
            self._output.close()
            with self._control_lock:
                self._control.close()
            self._closed = True
            with self._journal_lock:
                if self._journal is not None:
                    self._journal_snapshot = self._journal.stats()
                    self._journal.close()
                    self._journal = None

    def _monitor_control(self):
        while not self._control_stop.wait(.1):
            self._read_errors()
            if not self._process.is_alive():
                self._read_errors()
                return

    def _read_errors(self):
        if self._closed:
            return
        with self._control_lock:
            try:
                while self._control.poll():
                    kind, value = self._control.recv()
                    if kind == 'error':
                        with self._lock:
                            if not self._error or self._error == 'Capture journal producer exited':
                                self._error = value
                    elif kind == 'state':
                        with self._lock:
                            self._route_state = value
                            self._route_observed_at = time.monotonic()
                            self._iface = value.get('selected_iface') or self._iface
            except (EOFError, OSError):
                pass

    def selected_iface(self):
        self._read_errors()
        with self._lock:
            return self._iface

    def capture_status(self):
        self._read_errors()
        with self._journal_lock:
            journal_stats = self._journal.stats() if self._journal is not None else self._journal_snapshot
        with self._counters.get_lock():
            received, accepted, dropped, pending = self._counters[:]
        with self._lock:
            running = self._process.is_alive() and not self._complete.is_set()
            route_state = dict(self._route_state)
            age = None if self._route_observed_at is None else max(0, time.monotonic() - self._route_observed_at)
            if running and age is not None and route_state.get('driver_stats'):
                driver = route_state['driver_stats'] = dict(route_state['driver_stats'])
                sample_age = driver.get('sample_age_seconds')
                driver['sample_age_seconds'] = None if sample_age is None else round(sample_age + age, 3)
                if sample_age is None or sample_age + age > 5:
                    driver['coverage_complete'] = False
            error = self._error
            if not running and not self._stopping.is_set():
                error = error or 'Capture child is not running'
            journal_pressure = journal_stats.get('journal_pending_records', 0) >= self._capacity
            driver_drops = (self._route_state.get('driver_stats') or {}).get('buffer_dropped_reported') or 0
            stale_control = running and age is not None and age > 5
            return dict(running=running, capture_started_at=self._started,
                        elapsed_seconds=max(0, time.time()-self._started) if self._started else 0,
                        capture_error=error, health='critical' if error or dropped or self._callback_errors else 'degraded' if journal_pressure or stale_control or (running and (driver_drops or self._route_state.get('raw_buffer_pressure') or self._route_state.get('route_warning') or self._route_state.get('capture_callback_errors'))) else 'healthy' if running else 'idle',
                        **route_state, control_sample_age_seconds=age,
                        mode='process_journal' if self._journal_path else 'process', child_pid=self._process.pid, ipc_capacity=self._capacity if not self._journal_path else None,
                        ipc_received=received, ipc_accepted=accepted, ipc_dropped=dropped,
                        ipc_pending=journal_stats.get('journal_pending_records', pending), ipc_batch_max=32,
                        **journal_stats,
                        journal_backlog_warning_records=self._capacity if self._journal_path else None,
                        journal_acknowledged_records=self._journal_acknowledged if self._journal_path else None,
                        journal_failure_stage=self._journal_failure_stage,
                        ipc_delivered=self._delivered, ipc_callback_errors=self._callback_errors)

    def shutdown_ready(self):
        if self._process is None or self._process.is_alive() or not self._complete.is_set() or not self._closed:
            return False
        status = self.capture_status()
        return status.get('ipc_pending') == 0 and (
            not self._journal_path or status.get('journal_pending_records') == 0)
