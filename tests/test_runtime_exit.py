import os
import threading
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from backend.app import main
from backend.app.security import require_trusted_client
from backend.app.services.sniffer_service import (
    CaptureStartUnavailableError, CaptureStopUnavailableError, SnifferService,
)


class RuntimeExitTests(unittest.TestCase):
    def service(self, flush=True):
        service = SnifferService.__new__(SnifferService)
        service._lifecycle_lock = threading.RLock()
        service._exit_prepared = False
        service._stop_session = Mock(return_value={'running': False})
        service._persistence = Mock()
        service._persistence.flush.return_value = flush
        return service

    def test_stop_and_persistence_flush_are_required_before_acknowledgement(self):
        service = self.service()
        order = []
        service._stop_session.side_effect = lambda: order.append('stop') or {'running': False}
        service._persistence.flush.side_effect = lambda: order.append('flush') or True
        self.assertEqual(service.prepare_exit(), {'running': False, 'exit_prepared': True})
        self.assertEqual(order, ['stop', 'flush'])
        with self.assertRaises(CaptureStartUnavailableError):
            service.start()

    def test_capture_drain_failure_cannot_acknowledge_exit(self):
        service = self.service()
        service._stop_session.side_effect = CaptureStopUnavailableError('still draining')
        with self.assertRaises(CaptureStopUnavailableError):
            service.prepare_exit()
        service._persistence.flush.assert_not_called()
        self.assertFalse(service._exit_prepared)

    def test_persistence_failure_can_be_retried(self):
        service = self.service(flush=False)
        with self.assertRaises(CaptureStopUnavailableError):
            service.prepare_exit()
        self.assertFalse(service._exit_prepared)
        service._persistence.flush.return_value = True
        self.assertTrue(service.prepare_exit()['exit_prepared'])

    def test_running_state_never_receives_exit_acknowledgement(self):
        service = self.service()
        service._stop_session.return_value = {'running': True}
        with self.assertRaises(CaptureStopUnavailableError):
            service.prepare_exit()
        self.assertFalse(service._exit_prepared)
        service._persistence.flush.assert_not_called()

    def test_repeated_prepare_is_safe(self):
        service = self.service()
        self.assertEqual(service.prepare_exit(), service.prepare_exit())

    def test_endpoint_requires_token_and_returns_retryable_drain_failure(self):
        previous = main.app.dependency_overrides.copy()
        main.app.dependency_overrides[require_trusted_client] = lambda: None
        try:
            with patch.dict(os.environ, {'NETBOT_LOCAL_TOKEN': 'unit-test-exit-token'}):
                with patch.object(main, 'sniffer_service') as service, patch.object(main, 'enforce_rate_limit'):
                    client = TestClient(main.app)
                    self.assertEqual(client.post('/api/runtime/prepare-exit').status_code, 401)
                    service.prepare_exit.assert_not_called()
                    service.prepare_exit.side_effect = CaptureStopUnavailableError('pending')
                    headers = {'X-NetBot-Token': 'unit-test-exit-token'}
                    self.assertEqual(client.post('/api/runtime/prepare-exit', headers=headers).status_code, 503)
                    service.prepare_exit.side_effect = None
                    service.prepare_exit.return_value = {'running': False, 'exit_prepared': True}
                    response = client.post('/api/runtime/prepare-exit', headers=headers)
                    self.assertEqual(response.status_code, 200)
                    self.assertTrue(response.json()['exit_prepared'])
        finally:
            main.app.dependency_overrides.clear()
            main.app.dependency_overrides.update(previous)
