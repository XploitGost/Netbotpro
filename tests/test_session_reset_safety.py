import threading
import unittest
from unittest.mock import Mock
from backend.app.services.sniffer_service import SnifferService, SessionResetUnavailableError, CaptureStopUnavailableError


class SessionResetSafetyTests(unittest.TestCase):
    def service(self, engine=None):
        service = object.__new__(SnifferService)
        service._lifecycle_lock = threading.RLock()
        service._lock = threading.Lock()
        service._engine = engine
        service._state = Mock()
        service.drain_packet_queue = Mock(return_value=False)
        return service

    def test_running_capture_cannot_clear_state(self):
        service = self.service(object())
        with self.assertRaises(SessionResetUnavailableError):
            service.reset_session()
        service._state.reset.assert_not_called()
        service.drain_packet_queue.assert_not_called()

    def test_drain_timeout_cannot_clear_state(self):
        service = self.service()
        with self.assertRaises(SessionResetUnavailableError):
            service.reset_session()
        service._state.reset.assert_not_called()

    def test_driver_stop_failure_preserves_handle_for_retry(self):
        engine = Mock()
        engine.stop.side_effect = OSError('driver busy')
        service = self.service(engine)
        with self.assertRaises(CaptureStopUnavailableError):
            service.stop()
        self.assertIs(service._engine, engine)
        service.drain_packet_queue.assert_not_called()
        engine.stop.side_effect = None
        service.drain_packet_queue.return_value = True
        service.get_state = Mock(return_value={'running':False})
        service._publisher = Mock()
        self.assertFalse(service.stop()['running'])
        self.assertIsNone(service._engine)

    def test_drain_timeout_does_not_publish_successful_stop(self):
        service = self.service()
        service._publisher = Mock()
        with self.assertRaises(CaptureStopUnavailableError):
            service.stop()
        service._publisher.publish_state.assert_not_called()
