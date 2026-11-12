"""Isolated Windows service probe; synthetic by default, live capture explicit.

Only numeric summaries leave the temporary workspace. This is not a UI soak or
a driver-loss guarantee. Run this script in a fresh Python process.
"""
from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import traceback

import psutil

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class FixtureCapture:
    def __init__(self, callback):
        self.callback = callback
        self.stopping = threading.Event()

    def start(self, iface=None):
        self.thread = threading.Thread(target=self._emit, daemon=True)
        self.thread.start()

    def _emit(self):
        rate = int(os.environ['NETBOT_PROBE_RATE'])
        index, started = 0, time.monotonic()
        while not self.stopping.is_set():
            self.callback({'ts': datetime.now(timezone.utc).isoformat(),
                           'src': '192.0.2.10', 'dst': '198.51.100.20',
                           'proto': 'TCP', 'sport': 50000 + index % 8,
                           'dport': 443, 'length': 100, 'flags': 'A',
                           'direction': 'OUTGOING', 'summary': 'Synthetic probe',
                           'tls_alpn': [] if index % 2 else ['h2', 'http/1.1']})
            index += 1
            self.stopping.wait(max(0, started + index / rate - time.monotonic()))

    def stop(self):
        self.stopping.set()
        self.thread.join(timeout=2)

    def selected_iface(self):
        return 'fixture'

    def capture_status(self):
        return {'running': not self.stopping.is_set()}


class FixtureProvider:
    def create_session(self, callback):
        from core.capture.process_session import ProcessCaptureSession
        return ProcessCaptureSession(callback, factory=FixtureCapture,
                                     journal_path=os.environ['NETBOT_CAPTURE_JOURNAL_PATH'])

    def describe_interface(self, candidate):
        return 'fixture'

    def preflight(self):
        from core.capture.contracts import CapturePreflightReport
        return CapturePreflightReport('fixture', 'windows', True, True, False)


def isolated_environment(folder: Path, rate: int) -> dict[str, str]:
    env = dict(os.environ)
    env.update({
        'NETBOT_DATA_DIR': str(folder / 'data'),
        'NETBOT_LOG_DIR': str(folder / 'logs'),
        'NETBOT_CONFIG_DIR': str(folder / 'config'),
        'NETBOT_DB_PATH': str(folder / 'history.db'),
        'NETBOT_FLOW_DB_PATH': str(folder / 'flows.db'),
        'NETBOT_CAPTURE_JOURNAL_PATH': str(folder / 'journal.db'),
        'NETBOT_CAPTURE_JOURNAL': '1', 'NETBOT_CAPTURE_PROCESS': '1',
        'NETBOT_JOURNAL_ACK_MODE': 'history', 'NETBOT_PROBE_RATE': str(rate),
        'NETBOT_STABILITY_RECORDING': '0', 'NETBOT_PROFILE_STAGES': '0',
    })
    return env


def verify_counts(capture: dict, persistence: dict, rows: int) -> list[str]:
    reasons = []
    acknowledged = capture.get('journal_acknowledged_records', 0)
    if not acknowledged:
        reasons.append('no_confirmed_packets')
    if capture.get('ipc_accepted') != acknowledged:
        reasons.append('accepted_acknowledged_mismatch')
    if rows != acknowledged or persistence.get('persisted_packets') != rows:
        reasons.append('history_acknowledged_mismatch')
    if capture.get('journal_pending_records') != 0:
        reasons.append('journal_not_drained')
    if capture.get('ipc_dropped') or capture.get('ipc_callback_errors'):
        reasons.append('capture_delivery_errors')
    if capture.get('capture_error'):
        reasons.append('capture_reported_error')
    if (capture.get('driver_stats') or {}).get('buffer_dropped_reported'):
        reasons.append('driver_reported_buffer_drops')
    if any(persistence.get(key) for key in ('failed_writes', 'dropped_writes', 'skipped_writes')):
        reasons.append('history_write_errors')
    return reasons


def worker(duration: float, live: bool) -> dict:
    from backend.app.services.settings_service import update_settings
    update_settings({'persist_logs': True, 'auto_block': False,
                     'payload_capture_enabled': False, 'capture_mode': 'metadata',
                     'sniffer_sample_rate': 1})
    from backend.app.services.event_bus import EventBus
    from backend.app.services.sniffer_service import SnifferService
    from core.netbotpro_logging import config

    bus = EventBus()
    service = SnifferService(bus, capture_provider=None if live else FixtureProvider())
    completion_ms = deque(maxlen=512)
    completion_failure = {}
    tickets = deque(maxlen=1)
    original_submit = service._history_delivery._submit

    def measured_submit(records):
        ticket = original_submit(records)
        tickets.append(ticket)
        return ticket

    service._history_delivery._submit = measured_submit
    original_complete = service._history_delivery.complete

    def measured_complete(identifier, results):
        started = time.monotonic()
        try:
            return original_complete(identifier, results)
        except Exception as exc:
            completion_failure.update(
                completion_error_type=type(exc).__name__,
                completion_frames=[f'{Path(frame.filename).name}:{frame.name}:{frame.lineno}'
                                   for frame in traceback.extract_tb(exc.__traceback__)[-6:]],
                ticket_status=tickets[-1].wait(0).status if tickets else None,
            )
            raise
        finally:
            completion_ms.append((time.monotonic() - started) * 1000)

    service._history_delivery.complete = measured_complete
    peak_pending = 0
    try:
        service.start()
        started = time.monotonic()
        while time.monotonic() - started < duration:
            state = service.get_state()
            peak_pending = max(peak_pending, state.get('journal_pending_records') or 0)
            if not state.get('running') or state.get('ipc_callback_errors'):
                break
            time.sleep(.25)
        stop_started = time.monotonic()
        service.stop()
        if not service._persistence.flush(timeout_sec=10):
            raise RuntimeError('Probe history did not drain')
        stop_ms = (time.monotonic() - stop_started) * 1000
        capture = service._capture_runtime_state()
        persistence = service._persistence.stats()
        driver = capture.get('driver_stats') or {}
        rows = config.get_conn().execute('SELECT COUNT(*) FROM packets').fetchone()[0]
        reasons = verify_counts(capture, persistence, rows)
        latencies = sorted(completion_ms)
        report = {
            'ok': not reasons, 'reasons': reasons,
            'mode': 'live' if live else 'synthetic',
            'scope': 'service_analysis_history_no_ui',
            'duration_sec': round(time.monotonic() - started, 3),
            'history_rows': rows, 'acknowledged': capture.get('journal_acknowledged_records'),
            'accepted': capture.get('ipc_accepted'),
            'pending_final': capture.get('journal_pending_records'),
            'pending_peak_sampled': peak_pending,
            'completion_tail_samples': len(latencies),
            'completion_tail_p95_ms': round(latencies[max(0, int(len(latencies) * .95) - 1)], 3) if latencies else None,
            'stop_and_flush_ms': round(stop_ms, 3),
            'write_p95_ms': persistence.get('p95_flush_ms'),
            'history_failed': persistence.get('failed_writes'),
            'history_dropped': persistence.get('dropped_writes'),
            'driver_stats_available': bool(capture.get('driver_stats')),
            'driver_buffer_dropped_reported': driver.get('buffer_dropped_reported'),
            'driver_coverage_complete': driver.get('coverage_complete'),
        }
    except Exception as exc:
        capture = service._capture_runtime_state()
        report = {'ok': False, 'reasons': ['service_probe_failed'],
                  'error_type': type(exc).__name__,
                  'failure_stage': capture.get('journal_failure_stage'),
                  'callback_errors': capture.get('ipc_callback_errors'),
                  'acknowledged': capture.get('journal_acknowledged_records'),
                  'pending_final': capture.get('journal_pending_records'),
                  'history_error_type': service._persistence.stats().get('last_error'),
                  **completion_failure}
    finally:
        try:
            service.close()
        except Exception as exc:
            report['ok'] = False
            report['cleanup_error_type'] = type(exc).__name__
        finally:
            bus.close()
            if config._CONN is not None:
                config._CONN.close()
                config._CONN = None
    return report


def stop_owned_tree(process: subprocess.Popen) -> None:
    try:
        parent = psutil.Process(process.pid)
        children = parent.children(recursive=True)
    except psutil.NoSuchProcess:
        return
    for item in list(reversed(children)) + [parent]:
        try:
            item.kill()
        except psutil.NoSuchProcess:
            pass
    psutil.wait_procs(children + [parent], timeout=5)


def workspace_bytes(folder: Path) -> int:
    size = 0
    for item in folder.rglob('*'):
        try:
            if item.is_file():
                size += item.stat().st_size
        except FileNotFoundError:
            pass
    return size


def run_probe(duration: float = 5, *, live: bool = False, rate: int = 100,
              max_bytes: int = 64 * 1024 * 1024) -> dict:
    if not 1 <= duration <= 120 or not 1 <= rate <= 500 or not 1024 * 1024 <= max_bytes <= 64 * 1024 * 1024:
        raise ValueError('Probe bounds: 1..120 seconds, 1..500 events/sec, 1..64 MiB')
    if os.name != 'nt':
        return {'ok': False, 'reasons': ['windows_dpapi_required']}
    if psutil.disk_usage(tempfile.gettempdir()).free < 512 * 1024**2:
        return {'ok': False, 'reasons': ['insufficient_scratch_disk_space']}
    with tempfile.TemporaryDirectory(prefix='netbot-history-probe-') as temporary:
        folder = Path(temporary)
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), '--worker', '--duration', str(duration)]
            + (['--live'] if live else []), cwd=folder,
            env=isolated_environment(folder, rate), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True,
        )
        started, peak_bytes, peak_rss = time.monotonic(), 0, 0
        failed = None
        owned_children = {}
        try:
            while process.poll() is None:
                size = workspace_bytes(folder)
                peak_bytes = max(peak_bytes, size)
                try:
                    owner = psutil.Process(process.pid)
                    children = owner.children(recursive=True)
                    owned_children.update((child.pid, child) for child in children)
                    peak_rss = max(peak_rss, sum(item.memory_info().rss for item in [owner] + children))
                except psutil.NoSuchProcess:
                    pass
                if len(owned_children) > 64:
                    failed = 'probe_process_budget_exceeded'
                    break
                if size > max_bytes:
                    failed = 'temporary_storage_budget_exceeded'
                    break
                if time.monotonic() - started > duration + 60:
                    failed = 'probe_deadline_exceeded'
                    break
                time.sleep(.25)
        finally:
            if process.poll() is None:
                stop_owned_tree(process)
            for child in owned_children.values():
                try:
                    if child.is_running():
                        child.kill()
                except psutil.NoSuchProcess:
                    pass
            psutil.wait_procs(list(owned_children.values()), timeout=5)
        output, _ = process.communicate(timeout=5)
        if failed:
            report = {'ok': False, 'reasons': [failed]}
        else:
            try:
                report = json.loads(output)
            except (ValueError, TypeError):
                report = {'ok': False, 'reasons': ['invalid_worker_report']}
            if process.returncode != 0:
                report['ok'] = False
        report.update(temporary_peak_bytes=peak_bytes, process_tree_peak_rss_mb=round(peak_rss / 1024**2, 3))
    report['temporary_workspace_removed'] = not folder.exists()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--duration', type=float, default=5)
    parser.add_argument('--rate', type=int, default=100)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        report = worker(args.duration, args.live) if args.worker else run_probe(args.duration, live=args.live, rate=args.rate)
    except Exception as exc:
        report = {'ok': False, 'reasons': ['probe_exception'], 'error_type': type(exc).__name__}
    print(json.dumps(report, sort_keys=True))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
