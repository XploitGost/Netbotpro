import threading
import unittest
from unittest.mock import Mock

from core.capture.process_session import ProcessCaptureSession
from backend.app.services.sniffer_service import (
    SnifferService, CaptureStopUnavailableError, SessionResetUnavailableError,
)


class RetainedJournalLifecycleTests(unittest.TestCase):
    def session(self):
        session = ProcessCaptureSession(lambda packet: None, journal_path='fixture-only')
        session._process = Mock()
        session._process.is_alive.return_value = False
        session._complete.set()
        session._closed = True
        session._journal = None
        session._journal_failure_stage = 'completion'
        session._journal_snapshot = {'journal_pending_records': 10}
        return session

    def service(self, engine):
        service = SnifferService.__new__(SnifferService)
        service._lock = threading.Lock()
        service._lifecycle_lock = threading.RLock()
        service._engine = engine
        service._final_capture_status = None
        service.drain_packet_queue = Mock(return_value=True)
        service._publisher = Mock()
        service.get_state = lambda: dict(service._final_capture_status or {})
        service._persistence = Mock()
        service._persistence.flush.return_value = True
        service._exit_prepared = False
        return service

    def test_closed_retained_journal_is_recoverable_but_not_drained(self):
        session = self.session()
        self.assertTrue(session.recovery_ready())
        session.capture_status = lambda: {'ipc_pending': 10, 'journal_pending_records': 10}
        self.assertFalse(session.shutdown_ready())
        for field, value in (('_closed', False), ('_journal', object()), ('_journal_path', None),
                             ('_journal_failure_stage', None), ('_journal_failure_stage', 'unknown')):
            original = getattr(session, field)
            setattr(session, field, value)
            self.assertFalse(session.recovery_ready(), field)
            setattr(session, field, original)
        session._process.is_alive.return_value = True
        self.assertFalse(session.recovery_ready())
        session._process.is_alive.return_value = False
        session._complete.clear()
        self.assertFalse(session.recovery_ready())
        session._complete.set()
        for value in (0, -1, None, '10', True):
            session._journal_snapshot['journal_pending_records'] = value
            self.assertFalse(session.recovery_ready())

    def test_stop_detaches_only_closed_recoverable_session_and_keeps_critical_state(self):
        engine = Mock(spec=ProcessCaptureSession)
        engine.stop.side_effect = RuntimeError('fixture failure')
        engine.shutdown_ready.return_value = False
        engine.recovery_ready.return_value = True
        engine.capture_status.return_value = {
            'running': False, 'health': 'critical', 'capture_error': 'fixture failure',
            'journal_pending_records': 10, 'journal_retained_for_replay': True}
        service = self.service(engine)
        state = service.stop()
        self.assertIsNone(service._engine)
        self.assertEqual(state['health'], 'critical')
        self.assertEqual(state['journal_pending_records'], 10)
        self.assertTrue(state['journal_retained_for_replay'])
        self.assertEqual(service.prepare_exit(), {**state, 'exit_prepared': True})

    def test_active_or_unclosed_session_still_blocks_stop_and_exit(self):
        engine = Mock(spec=ProcessCaptureSession)
        engine.stop.side_effect = RuntimeError('fixture failure')
        engine.shutdown_ready.return_value = False
        engine.recovery_ready.return_value = False
        service = self.service(engine)
        with self.assertRaises(CaptureStopUnavailableError):
            service.stop()
        with self.assertRaises(CaptureStopUnavailableError):
            service.prepare_exit()
        self.assertIs(service._engine, engine)
        self.assertIsNone(service._final_capture_status)
        self.assertFalse(service._exit_prepared)

    def test_history_mode_requires_writer_barrier_even_without_deferred_flow(self):
        service = self.service(None)
        service._deferred_flow_snapshots = False
        service._history_delivery = object()
        service._persistence.flush.return_value = False
        with self.assertRaises(SessionResetUnavailableError):
            service.reset_session()
        service._persistence.flush.assert_called_once()
