"""Opt-in bounded soak telemetry: numeric counters only, no packet identifiers."""
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import threading
import time

ERROR_COUNTERS = (
    'rejected', 'callback_errors', 'capture_callback_errors', 'detector_errors',
    'storage_dropped', 'storage_failed', 'driver_buffer_dropped',
    'driver_interface_dropped_raw', 'ml_training_failures', 'flow_compaction_errors',
)


def number(value):
    return value if type(value) is int or (type(value) is float and math.isfinite(value)) else None


def project(snapshot):
    capture = snapshot.get('capture') or {}
    driver = capture.get('driver_stats') or {}
    detection = snapshot.get('alert_engine') or {}
    training = detection.get('ml_training') or {}
    storage = snapshot.get('persistence') or {}
    profile = ((snapshot.get('stage_profile') or {}).get('stages') or {}).get('total_packet') or {}
    capture_profile = capture.get('capture_profile') or {}
    raw = capture.get('raw_buffers')
    row = dict(capture_running=bool(capture.get('running')),
               capture_error=bool(capture.get('capture_error')),
               route_waiting=bool(capture.get('route_warning')),
               driver_available=driver.get('available') is True,
               driver_coverage_complete=driver.get('coverage_complete') is True)
    row['raw_buffer_pressure'] = bool(capture.get('raw_buffer_pressure'))
    for key, field in (('raw_pending_frames', 'queued_frames'), ('raw_pending_bytes', 'queued_bytes'),
                       ('raw_capacity_bytes', 'capacity_bytes'), ('raw_high_water_bytes', 'high_water_bytes')):
        row[key] = sum(number(item.get(field)) or 0 for item in raw) if isinstance(raw, list) else None
    for name, source, field in (
        ('session', capture, 'capture_started_at'), ('route_switches', capture, 'route_switches'),
        ('pending_warning_threshold', capture, 'journal_backlog_warning_records'),
        ('received', capture, 'ipc_received'), ('accepted', capture, 'ipc_accepted'),
        ('analyzed', capture, 'ipc_delivered'), ('pending', capture, 'ipc_pending'),
        ('rejected', capture, 'ipc_dropped'), ('callback_errors', capture, 'ipc_callback_errors'),
        ('capture_callback_errors', capture, 'capture_callback_errors'),
        ('driver_received', driver, 'received_reported'),
        ('driver_samples', driver, 'samples'),
        ('driver_sample_age_seconds', driver, 'sample_age_seconds'),
        ('driver_buffer_dropped', driver, 'buffer_dropped_reported'),
        ('driver_interface_dropped_raw', driver, 'interface_dropped_raw'),
        ('detector_errors', detection, 'errors_total'), ('alerts_generated', detection, 'alerts_generated_total'),
        ('ml_training_attempts', training, 'training_attempts'),
        ('ml_training_successes', training, 'training_successes'),
        ('ml_training_failures', training, 'training_failures'),
        ('ml_score_cache_hits', training, 'score_cache_hits'),
        ('ml_score_cache_misses', training, 'score_cache_misses'),
        ('storage_dropped', storage, 'events_dropped_total'), ('storage_failed', storage, 'events_failed_total'),
        ('storage_pending', storage, 'queue_depth'),
        ('analysis_p50_ms', profile, 'p50_ms'), ('analysis_p95_ms', profile, 'p95_ms'),
        ('capture_metadata_p95_ms', capture_profile, 'metadata_p95_ms'),
        ('capture_metadata_max_ms', capture_profile, 'metadata_max_ms'),
        ('capture_emit_p95_ms', capture_profile, 'emit_p95_ms'),
        ('capture_emit_max_ms', capture_profile, 'emit_max_ms'),
        ('alerts_coalesced', snapshot.get('auto_block') or {}, 'repeated_alerts_coalesced_total'),
        ('flow_total', snapshot.get('flow_memory') or {}, 'total_flows'),
        ('flow_hot', snapshot.get('flow_memory') or {}, 'hot_flows'),
        ('flow_compressed', snapshot.get('flow_memory') or {}, 'compressed_flows'),
        ('flow_compressed_bytes', snapshot.get('flow_memory') or {}, 'compressed_bytes'),
        ('flow_compaction_errors', snapshot.get('flow_memory') or {}, 'errors_total'),
    ):
        row[name] = number(source.get(field))
    return row


def resource_sample(child_pid):
    import psutil
    result = {}
    for label, pid in (('backend', os.getpid()), ('capture', child_pid)):
        if not pid:
            continue
        try:
            process = psutil.Process(pid)
            cpu = process.cpu_times()
            result[label + '_rss_bytes'] = process.memory_info().rss
            result[label + '_cpu_seconds'] = cpu.user + cpu.system
            result[label + '_pid'] = pid
        except (psutil.Error, OSError):
            continue
    return result


class StabilityRecorder:
    def __init__(self, snapshot, path, *, interval=5, max_bytes=2*1024*1024,
                 backups=3, resources=resource_sample, clock=time.monotonic):
        self._snapshot, self._resources, self._clock = snapshot, resources, clock
        self.path = Path(path)
        self.interval = max(.1, float(interval))
        self.max_bytes, self.backups = max(1024, int(max_bytes)), max(1, min(5, backups))
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._previous = None
        self._known_error_fields = set()
        self._summary = dict(samples=0, active_seconds=0.0, target_seconds=4*60*60,
                             max_pending=0, last_pending=None, issues_observed=False,
                             driver_unknown_samples=0, driver_incomplete_samples=0,
                             sampling_gaps=0, write_errors=0, last_error_type='',
                             resource_unknown_samples=0,
                             backlog_warning_samples=0, capture_sessions=0,
                             error_intervals=0, counter_reset_intervals=0,
                             qualified_continuous_seconds=0.0, max_qualified_continuous_seconds=0.0,
                             unobserved_seconds_total=0.0, max_sampling_gap_seconds=0.0,
                             last_sampling_gap_utc=None, last_gap_received_delta=None,
                             last_gap_analyzed_delta=None, last_gap_driver_samples_delta=None,
                             max_backend_rss_bytes=0, max_capture_rss_bytes=0,
                             assessment='incomplete')

    def start(self):
        self._thread = threading.Thread(target=self._run, name='stability-recorder', daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            self.sample()
            self._stop.wait(self.interval)

    def sample(self):
        try:
            snapshot = self._snapshot()
            row = project(snapshot)
            usage = self._resources((snapshot.get('capture') or {}).get('child_pid'))
            for key in ('backend_rss_bytes', 'capture_rss_bytes', 'backend_cpu_seconds', 'capture_cpu_seconds', 'backend_pid', 'capture_pid'):
                row[key] = number(usage.get(key))
            now = self._clock()
            row['utc'] = datetime.now(timezone.utc).isoformat()
            with self._lock:
                previous = self._previous
                delta = now - previous[0] if previous else 0
                same = previous and row['session'] is not None and row['session'] == previous[1]['session']
                gap = delta > self.interval * 3
                row['sample_gap_seconds'] = delta if gap else 0.0
                row['received_per_second'] = None
                row['analyzed_per_second'] = None
                for field in ('received', 'analyzed'):
                    if same and not gap and delta > 0 and row[field] is not None and previous[1][field] is not None and row[field] >= previous[1][field]:
                        row[field + '_per_second'] = round((row[field]-previous[1][field])/delta, 2)
                for label in ('backend', 'capture'):
                    row[label + '_cpu_percent_one_core'] = None
                    key = label + '_cpu_seconds'
                    if previous and not gap and delta > 0 and row[label + '_pid'] is not None and row[label + '_pid'] == previous[1][label + '_pid'] and row[key] is not None and previous[1][key] is not None:
                        row[label + '_cpu_percent_one_core'] = round(max(0, row[key]-previous[1][key])/delta*100, 2)
                summary = self._summary
                summary['samples'] += 1
                if row['capture_running'] and (not previous or not same):
                    summary['capture_sessions'] += 1
                if gap:
                    summary['sampling_gaps'] += 1
                    summary['unobserved_seconds_total'] += delta
                    summary['max_sampling_gap_seconds'] = max(summary['max_sampling_gap_seconds'], delta)
                    summary['last_sampling_gap_utc'] = row['utc']
                    for field in ('received', 'analyzed', 'driver_samples'):
                        current, prior = row[field], previous[1][field]
                        summary['last_gap_' + field + '_delta'] = (current - prior if same and current is not None
                                                                 and prior is not None and current >= prior else None)
                elif same and row['capture_running'] and previous[1]['capture_running']:
                    summary['active_seconds'] += delta
                summary['last_pending'] = row['pending']
                summary['max_pending'] = max(summary['max_pending'], row['pending'] or 0)
                backlog = row['raw_buffer_pressure'] or (row['pending'] is not None and row['pending_warning_threshold'] is not None and row['pending'] >= row['pending_warning_threshold'])
                summary['backlog_warning_samples'] += int(backlog)
                for label in ('backend', 'capture'):
                    field = label + '_rss_bytes'
                    summary['max_' + field] = max(summary['max_' + field], row[field] or 0)
                if row['capture_running']:
                    summary['driver_unknown_samples'] += int(not row['driver_available'])
                    age = row['driver_sample_age_seconds']
                    summary['driver_incomplete_samples'] += int(not row['driver_coverage_complete'] or age is None or age > 5)
                    summary['resource_unknown_samples'] += int(row['backend_rss_bytes'] is None or row['capture_rss_bytes'] is None)
                observed_errors = row['capture_error'] or any((row[key] or 0) > 0 for key in ERROR_COUNTERS)
                if not same:
                    self._known_error_fields.clear()
                interval_errors = bool(row['capture_error'])
                counter_reset = False
                for key in ERROR_COUNTERS:
                    current = row[key]
                    prior = previous[1][key] if same and not gap else None
                    if current is None:
                        interval_errors |= key in self._known_error_fields
                        continue
                    self._known_error_fields.add(key)
                    if prior is None:
                        interval_errors |= current > 0
                    else:
                        interval_errors |= current != prior
                        counter_reset |= current < prior
                row['error_interval'] = bool(interval_errors)
                row['error_counter_reset'] = bool(counter_reset)
                summary['error_intervals'] += int(interval_errors)
                summary['counter_reset_intervals'] += int(counter_reset)
                # Historical failures remain sticky, but a later clean window can qualify.
                summary['issues_observed'] |= bool(observed_errors or counter_reset)
                age = row['driver_sample_age_seconds']
                row['qualified_sample'] = bool(row['capture_running'] and row['driver_available']
                    and row['driver_coverage_complete'] and age is not None and 0 <= age <= 5
                    and row['backend_rss_bytes'] is not None and row['capture_rss_bytes'] is not None
                    and not interval_errors and not backlog)
                if same and not gap and delta > 0 and row['qualified_sample'] and previous[1].get('qualified_sample'):
                    summary['qualified_continuous_seconds'] += delta
                else:
                    summary['qualified_continuous_seconds'] = 0.0
                summary['max_qualified_continuous_seconds'] = max(summary['max_qualified_continuous_seconds'], summary['qualified_continuous_seconds'])
                complete = summary['qualified_continuous_seconds'] >= summary['target_seconds']
                review = any(summary[key] for key in ('issues_observed', 'write_errors', 'sampling_gaps', 'backlog_warning_samples'))
                summary['assessment'] = 'needs_review' if review else 'ready_for_review' if complete else 'incomplete'
                summary['last_sample_utc'] = row['utc']
                self._previous = now, row
                self._write(row)
        except Exception as exc:
            with self._lock:
                self._summary['write_errors'] += 1
                self._summary['last_error_type'] = type(exc).__name__
                self._summary['assessment'] = 'needs_review'
                self._summary['qualified_continuous_seconds'] = 0.0
                if self._previous is not None:
                    self._previous[1]['qualified_sample'] = False

    def _write(self, row):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(row, ensure_ascii=True, allow_nan=False) + '\n'
        if self.path.exists() and self.path.stat().st_size + len(line.encode('utf-8')) > self.max_bytes:
            for index in range(self.backups, 0, -1):
                source = self.path if index == 1 else Path(str(self.path) + f'.{index-1}')
                destination = Path(str(self.path) + f'.{index}')
                if source.exists():
                    os.replace(source, destination)
        with self.path.open('a', encoding='utf-8') as stream:
            stream.write(line)
        destination = self.path.with_suffix('.summary.json')
        temporary = destination.with_suffix('.tmp')
        temporary.write_text(json.dumps(self._summary, ensure_ascii=True, allow_nan=False), encoding='utf-8')
        os.replace(temporary, destination)

    def stats(self):
        with self._lock:
            reasons = [reason for key, reason in (
                ('issues_observed', 'stability_recorded_errors'), ('write_errors', 'stability_write_errors'),
                ('sampling_gaps', 'stability_sampling_gaps'), ('backlog_warning_samples', 'stability_backlog_observed'))
                if self._summary[key]]
            return dict(enabled=True, resource_scope='backend_and_capture',
                        health='degraded' if reasons else 'healthy', pressure_reasons=reasons,
                        window_assessment=('ready_for_review' if self._summary['qualified_continuous_seconds'] >= self._summary['target_seconds'] else 'incomplete'),
                        interval_seconds=self.interval, **self._summary)

    def close(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(3)
