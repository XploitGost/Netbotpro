"""Fault injection only inside journal_history_probe's disposable worker."""
import os
import sqlite3
import threading
import time
from unittest.mock import patch


class ProbeCheckFailed(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise ProbeCheckFailed(code)


def slow_stop(service, entered, release, config):
    finished = threading.Event()
    errors = []
    stopping = None
    try:
        service.start()
        require(entered.wait(5), 'history_writer_not_entered')
        engine = service._engine
        require(engine.capture_status()['journal_acknowledged_records'] == 0, 'premature_acknowledgement')

        def stop():
            try:
                service.stop()
            except Exception as exc:
                errors.append(type(exc).__name__)
            finally:
                finished.set()

        stopping = threading.Thread(target=stop, daemon=True)
        stopping.start()
        require(not finished.wait(.1), 'stop_abandoned_inflight_history')
        require(not engine.recovery_ready(), 'active_consumer_reported_recoverable')
        require(config.get_conn().execute('SELECT COUNT(*) FROM packets').fetchone()[0] == 0,
                'history_written_before_gate_release')
        release.set()
        require(finished.wait(5), 'normal_stop_did_not_finish')
        require(not errors, 'normal_stop_failed')
        final = service._capture_runtime_state()
        require(service._persistence.flush(timeout_sec=5), 'writer_did_not_drain')
        rows = config.get_conn().execute('SELECT COUNT(*) FROM packets').fetchone()[0]
        require(rows == final['ipc_accepted'] == final['journal_acknowledged_records'] > 0,
                'slow_stop_count_mismatch')
        require(final['journal_pending_records'] == 0, 'slow_stop_journal_not_drained')
        return {'ok': True, 'history_rows_final': rows,
                'acknowledged_final': final['journal_acknowledged_records'],
                'pending_final': 0, 'stop_waited_for_history': True}
    finally:
        release.set()
        if stopping is not None:
            stopping.join(timeout=6)


def recovery_worker(duration: float, scenario: str) -> dict:
    from scripts.qa.journal_history_probe import validate_worker_workspace
    validate_worker_workspace()
    if scenario not in {'locked', 'locked-reopen', 'late-commit', 'slow-stop'} or not 1 <= duration <= 120:
        raise ValueError('Invalid bounded recovery scenario')
    from backend.app.services.settings_service import update_settings
    update_settings({'persist_logs': True, 'auto_block': False,
                     'payload_capture_enabled': False, 'capture_mode': 'metadata',
                     'sniffer_sample_rate': 1})
    from backend.app.services.event_bus import EventBus
    from backend.app.services.sniffer_service import SnifferService
    from backend.app.services import sniffer_persistence
    from core.capture.journal import CaptureJournal
    from core.netbotpro_logging import config
    from scripts.qa.journal_history_probe import FixtureProvider

    bus = EventBus()
    service = SnifferService(bus, capture_provider=FixtureProvider())
    service._persistence._batch_writer._retry_max = 0
    entered, release = threading.Event(), threading.Event()
    original_insert = sniffer_persistence.insert_batch
    locker = None
    report = {'ok': False, 'scenario': scenario, 'mode': 'synthetic',
              'scope': 'service_storage_fault_replay_no_ui'}

    def delayed_insert(*args):
        entered.set()
        require(release.wait(8), 'fault_gate_not_released')
        return original_insert(*args)

    try:
        if scenario in {'locked', 'locked-reopen'}:
            # Only this worker's scratch DB: exercise real SQLite lock failure.
            config.get_conn().execute('PRAGMA busy_timeout=20')
            locker = sqlite3.connect(os.environ['NETBOT_DB_PATH'])
            locker.execute('BEGIN IMMEDIATE')
        elif scenario == 'late-commit':
            service._history_delivery._timeout = .05
        with patch.object(sniffer_persistence, 'insert_batch',
                          original_insert if scenario in {'locked', 'locked-reopen'} else delayed_insert):
            if scenario == 'slow-stop':
                report.update(slow_stop(service, entered, release, config))
                return report
            service.start()
            engine = service._engine
            if scenario == 'late-commit':
                require(entered.wait(5), 'history_writer_not_entered')
            require(engine._complete.wait(5), 'consumer_did_not_fail_closed')
            state = engine.capture_status()
            report.update(failure_stage=state['journal_failure_stage'],
                          acknowledged_before=state['journal_acknowledged_records'])
            require(state['journal_failure_stage'] == 'completion', 'wrong_failure_stage')
            require(state['journal_acknowledged_records'] == 0, 'premature_acknowledgement')
            stopped = service.stop()
            require(stopped['running'] is False, 'failed_producer_still_running')
            retained = stopped['journal_pending_records']
            require(retained > 0, 'failed_batch_not_retained')
            require(stopped['health'] == 'critical', 'failed_capture_reported_healthy')
            require(service._engine is None, 'failed_session_not_released')
            report['retained_before_replay'] = retained
            journal = CaptureJournal(os.environ['NETBOT_CAPTURE_JOURNAL_PATH'])
            try:
                first_ids = [row['capture_event_id'] for row in journal.first()[1]]
            finally:
                journal.close()
            report['history_rows_before_release'] = config.get_conn().execute('SELECT COUNT(*) FROM packets').fetchone()[0]
            require(report['history_rows_before_release'] == 0, 'write_confirmed_before_release')
            if locker is not None:
                locker.rollback()
                locker.close()
                locker = None
            release.set()
            # Settle any late write before a new analysis session can start.
            service._persistence.flush(timeout_sec=5)
        service._history_delivery._timeout = 10
        before = config.get_conn().execute('SELECT COUNT(*) FROM packets').fetchone()[0]
        report['history_rows_after_release'] = before
        require(before == (len(first_ids) if scenario == 'late-commit' else 0), 'unexpected_late_write_count')
        report['historical_failed_events'] = service._persistence.stats()['failed_writes']
        if scenario == 'locked-reopen':
            service.close()
            require(not service._packet_worker.is_alive(), 'old_service_worker_survived_close')
            bus.close()
            bus = EventBus()
            service = SnifferService(bus, capture_provider=FixtureProvider())
            report['service_reopened'] = True
        service.start()
        time.sleep(duration)
        service.stop()
        require(service._persistence.flush(timeout_sec=5), 'recovery_writer_did_not_drain')
        final = service._capture_runtime_state()
        connection = config.get_conn()
        rows, distinct = connection.execute('SELECT COUNT(*),COUNT(DISTINCT capture_event_id) FROM packets').fetchone()
        replayed = connection.execute(
            f"SELECT COUNT(*) FROM packets WHERE capture_event_id IN ({','.join('?' for _ in first_ids)})",
            first_ids).fetchone()[0]
        require(final['journal_pending_records'] == 0, 'recovery_journal_not_drained')
        require(final['journal_acknowledged_records'] == retained + final['ipc_accepted'], 'recovery_count_mismatch')
        require(rows == distinct == final['journal_acknowledged_records'], 'duplicate_or_missing_history')
        require(replayed == len(first_ids), 'original_occurrences_not_recovered')
        report.update(ok=True, history_rows_final=rows, distinct_occurrences=distinct,
                      acknowledged_final=final['journal_acknowledged_records'],
                      new_accepted=final['ipc_accepted'], pending_final=final['journal_pending_records'],
                      first_batch_recovered=replayed)
    except Exception as exc:
        report.update(ok=False, error_type=type(exc).__name__)
        if isinstance(exc, ProbeCheckFailed):
            report['check_failure'] = str(exc)
    finally:
        release.set()
        if locker is not None:
            locker.rollback()
            locker.close()
        try:
            service.close()
        except Exception as exc:
            report.update(ok=False, cleanup_error_type=type(exc).__name__)
        finally:
            bus.close()
            if config._CONN is not None:
                config._CONN.close()
                config._CONN = None
    return report
