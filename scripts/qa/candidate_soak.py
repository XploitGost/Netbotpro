"""Supervise a 5..30 minute packaged live UI test with disposable bounded storage."""
from __future__ import annotations

import argparse
from collections import deque
import json
import os
from pathlib import Path
import secrets
import re
import shutil
import subprocess
import sys
import tempfile
import time

import psutil

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.qa.journal_history_probe import workspace_bytes, stop_owned_tree

MIB = 1024**2


def budget_reason(*, elapsed, duration, storage, rss, free, children, log_bytes):
    if elapsed > duration + 120:
        return 'soak_deadline_exceeded'
    if storage > 512 * MIB:
        return 'soak_storage_budget_exceeded'
    if rss > 2048 * MIB:
        return 'soak_memory_budget_exceeded'
    if free < 2048 * MIB:
        return 'soak_disk_headroom_exhausted'
    if children > 64:
        return 'soak_process_budget_exceeded'
    if log_bytes > 2 * MIB:
        return 'soak_log_budget_exceeded'
    return None


def read_reports(log):
    if not log.exists():
        return []
    result = []
    with log.open('rb') as stream:
        data = stream.read(2 * MIB)
    for line in data.decode('utf-8', errors='replace').splitlines():
        try:
            row = json.loads(line)
            if isinstance(row, dict) and (row.get('stage') in {'capture_started', 'route_baseline_ready', 'capture_sample', 'capture_stopped'} or row.get('temporaryProfileRemoved') is True):
                result.append(row)
        except ValueError:
            pass
    return result


def retire_exited(observed, previous_cpu):
    for key, item in list(observed.items()):
        try:
            alive = item.is_running()
        except psutil.NoSuchProcess:
            alive = False
        if not alive:
            observed.pop(key, None)
            previous_cpu.pop(key, None)


def run_soak(executable, duration=900, require_vpn_cycle=False):
    if not isinstance(duration, int) or not 300 <= duration <= 1800:
        raise ValueError('Soak duration must be 300..1800 seconds')
    if os.name != 'nt':
        raise RuntimeError('Packaged candidate soak requires Windows')
    executable = Path(executable).resolve()
    if not executable.is_file():
        raise ValueError('Explicit candidate executable required')
    manifest = json.loads((executable.parents[2] / 'candidate.json').read_text(encoding='utf-8'))
    if Path(manifest.get('executable', '')).resolve() != executable or not re.fullmatch('[0-9a-f]{40}', manifest.get('revision', '')):
        raise ValueError('Candidate build manifest does not match the executable')
    node = shutil.which('node')
    if not node or shutil.disk_usage(tempfile.gettempdir()).free < 3 * 1024**3:
        raise RuntimeError('Node and at least 3 GiB free scratch space are required')
    with tempfile.TemporaryDirectory(prefix='netbot-candidate-soak-') as temporary:
        folder = Path(temporary).resolve()
        nonce = secrets.token_hex(24)
        policy = {'version': 1, 'nonce': nonce, 'durationSeconds': duration,
                  'maxProfileBytes': 512 * MIB, 'requireVpnCycle': bool(require_vpn_cycle)}
        (folder / 'policy.json').write_text(json.dumps(policy), encoding='utf-8')
        env = {**os.environ, 'NETBOT_CANDIDATE_EXE': str(executable),
               'NETBOT_SMOKE_PYTHON_BIN': sys.executable, 'NETBOT_CANDIDATE_DURATION': str(duration),
               'NETBOT_CANDIDATE_SOAK_ROOT': str(folder), 'NETBOT_CANDIDATE_SOAK_NONCE': nonce}
        log = folder / 'worker.log'
        started = time.monotonic()
        peak_storage = peak_rss = 0
        previous_cpu = {}
        total_cpu = 0.0
        observed = {}
        observed_total = active_peak = 0
        roles = {}
        series = deque(maxlen=128)
        reported = 0
        reason = None
        with log.open('wb') as output:
            process = subprocess.Popen([node, str(ROOT / 'frontend/desktop-reference/test-candidate-capture.mjs')],
                                       cwd=folder, env=env, stdout=output, stderr=output)
            try:
                while process.poll() is None:
                    elapsed = time.monotonic() - started
                    rss = 0
                    try:
                        owner = psutil.Process(process.pid)
                        items = [owner, *owner.children(recursive=True)]
                        for item in items:
                            try:
                                key = (item.pid, item.create_time())
                                if key not in observed:
                                    observed_total += 1
                                    command = item.cmdline()
                                    name = item.name().lower()
                                    role = ('interface_discovery' if '--capture-discovery-json' in command else
                                            'capture_probe' if '--capture-backend-probe' in command else
                                            'electron' if name == 'netbotpro candidate.exe' else
                                            'backend' if name == 'netbotpro-backend.exe' else
                                            'node' if name == 'node.exe' else 'other')
                                    roles[role] = roles.get(role, 0) + 1
                                observed[key] = item
                            except psutil.NoSuchProcess:
                                pass
                        retire_exited(observed, previous_cpu)
                        for key, item in list(observed.items()):
                            try:
                                rss += item.memory_info().rss
                                times = item.cpu_times()
                                cpu = times.user + times.system
                                total_cpu += max(0, cpu - previous_cpu.get(key, cpu))
                                previous_cpu[key] = cpu
                            except psutil.NoSuchProcess:
                                pass
                    except psutil.NoSuchProcess:
                        items = []
                    storage = workspace_bytes(folder)
                    active_peak = max(active_peak, len(observed))
                    peak_storage, peak_rss = max(peak_storage, storage), max(peak_rss, rss)
                    reason = budget_reason(elapsed=elapsed, duration=duration, storage=storage, rss=rss,
                        free=shutil.disk_usage(folder).free, children=len(observed), log_bytes=log.stat().st_size)
                    if reason:
                        break
                    rows = read_reports(log)
                    for row in rows[reported:]:
                        print(json.dumps(row), flush=True)
                    reported = len(rows)
                    if not series or elapsed - series[-1]['seconds'] >= 30:
                        sample = {'stage': 'resource_sample', 'seconds': round(elapsed, 1),
                            'aggregate_process_rss_mb': round(rss / MIB, 2), 'temporary_mb': round(storage / MIB, 2),
                            'active_processes': len(observed), 'observed_processes_total': observed_total,
                            'sampled_process_roles': dict(roles)}
                        series.append(sample)
                        print(json.dumps(sample), flush=True)
                    time.sleep(1)
            finally:
                if process.poll() is None:
                    stop_owned_tree(process)
                for item in observed.values():
                    try:
                        if item.is_running():
                            item.kill()
                    except psutil.NoSuchProcess:
                        pass
                psutil.wait_procs(list(observed.values()), timeout=5)
                process.wait(timeout=5)
        rows = read_reports(log)
        for row in rows[reported:]:
            print(json.dumps(row), flush=True)
        completed = next((row for row in reversed(rows) if row.get('temporaryProfileRemoved')), None)
        elapsed = time.monotonic() - started
        if reason is None:
            reason = ('candidate_worker_failed' if process.returncode else 'missing_candidate_report' if completed is None
                      else 'soak_completed_too_early' if elapsed < duration else None)
        report = {'ok': reason is None,
                  'reason': reason,
                  'candidate_source_revision': manifest['revision'],
                  'requested_seconds': duration, 'supervisor_seconds': round(elapsed, 2),
                  'temporary_peak_bytes': peak_storage, 'aggregate_process_peak_rss_mb': round(peak_rss / MIB, 2),
                  'sampled_aggregate_cpu_one_core_percent': round(100 * total_cpu / elapsed, 2),
                  'active_processes_peak': active_peak, 'observed_processes_total': observed_total,
                  'sampled_process_roles': roles, 'candidate': completed,
                  'resource_samples': list(series)}
    report['temporary_workspace_removed'] = not folder.exists()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', required=True)
    parser.add_argument('--duration', type=int, default=900)
    parser.add_argument('--require-vpn-cycle', action='store_true')
    args = parser.parse_args()
    report = run_soak(args.executable, args.duration, args.require_vpn_cycle)
    print(json.dumps(report), flush=True)
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
