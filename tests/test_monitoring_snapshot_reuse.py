import unittest
from unittest.mock import Mock, patch

from backend.app import main


class MonitoringSnapshotReuseTests(unittest.TestCase):
    def test_state_reads_capture_once_and_keeps_detached_capture_views(self):
        service = main.sniffer_service
        capture = {'running': False, 'health': 'healthy', 'raw_buffers': [{'queued_frames': 7}]}
        with patch.object(service, '_capture_runtime_state', return_value=capture) as read:
            state = service.get_state()
        read.assert_called_once_with()
        self.assertEqual(state['raw_buffers'], state['observability']['capture']['raw_buffers'])
        state['raw_buffers'][0]['queued_frames'] = 99
        self.assertEqual(state['observability']['capture']['raw_buffers'][0]['queued_frames'], 7)

    def test_supplied_empty_snapshot_is_not_resampled(self):
        with patch.object(main.sniffer_service, 'observability', side_effect=AssertionError('resampled')):
            result = main._observability_snapshot({})
        self.assertIn('websocket', result)
        self.assertIn('history', result)

    def test_unsupplied_snapshot_is_collected_once_without_duplicate_components(self):
        service = main.sniffer_service
        snapshot = {'capture': {'running': True}, 'packet_queue': {'current_depth': 3}}
        with patch.object(service, 'observability', return_value=snapshot) as collect, \
             patch.object(service, 'packet_queue_stats', side_effect=AssertionError('duplicate')):
            result = main._observability_snapshot()
        collect.assert_called_once_with()
        self.assertEqual(result['packet_queue'], snapshot['packet_queue'])
        self.assertIn('event_aggregator', result)

    def test_status_reuses_observability_from_state(self):
        snapshot = {'capture': {'running': True}, 'alert_engine': {'health': 'critical'}}
        state = {'running': True, 'observability': snapshot}
        with patch.object(main.sniffer_service, 'get_state', return_value=state), \
             patch.object(main.sniffer_service, 'observability', side_effect=AssertionError('resampled')):
            result = main.api_status(None)
        self.assertEqual(result['observability']['alert_engine']['health'], 'critical')
        self.assertEqual(result['sniffer'], state)

    def test_monitoring_reuses_observability_from_state(self):
        snapshot = {'capture': {'running': True}, 'packet_queue': {'current_depth': 4}}
        state = {'running': True, 'observability': snapshot}
        build = Mock(return_value={})
        with patch.object(main.sniffer_service, 'get_state', return_value=state), \
             patch.object(main.sniffer_service, 'observability', side_effect=AssertionError('resampled')), \
             patch.object(main, 'build_monitoring_metrics', build):
            main.api_monitoring_metrics(None, None)
        self.assertEqual(build.call_args.kwargs['observability']['packet_queue']['current_depth'], 4)
        self.assertIs(build.call_args.kwargs['sniffer_state'], state)


if __name__ == '__main__':
    unittest.main()
