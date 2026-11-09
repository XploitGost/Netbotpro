import os
import unittest
from unittest.mock import Mock, patch
from backend.app.services.sniffer_service import SnifferService


class JournalDetectionGuardTests(unittest.TestCase):
    def test_caught_detector_error_does_not_acknowledge_analysis(self):
        service = SnifferService.__new__(SnifferService)
        service._next_packet_id = lambda: 'test-packet'
        service._detection_pipeline = Mock()
        service._detection_pipeline.error_count.side_effect = [0, 1]
        service._detection_pipeline.analyze.return_value = []
        with patch.dict(os.environ, NETBOT_CAPTURE_JOURNAL='1'):
            with patch('backend.app.services.sniffer_service.current_payload_capture_settings', return_value={}):
                with self.assertRaisesRegex(RuntimeError, 'batch must be retained'):
                    service._process_packet({'src':'192.0.2.1'})

    def test_pipeline_exception_is_propagated_in_journal_mode(self):
        service = SnifferService.__new__(SnifferService)
        service._next_packet_id = lambda: 'test-packet'
        service._detection_pipeline = Mock()
        service._detection_pipeline.error_count.return_value = 0
        service._detection_pipeline.analyze.side_effect = ValueError('test error')
        with patch.dict(os.environ, NETBOT_CAPTURE_JOURNAL='1'):
            with patch('backend.app.services.sniffer_service.current_payload_capture_settings', return_value={}):
                with self.assertLogs('backend.app.services.sniffer_service', level='ERROR'):
                    with self.assertRaises(ValueError):
                        service._process_packet({'src':'192.0.2.1'})
