import asyncio
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import Mock, patch

from backend.app.repositories import MemoryHistoryRepository, PacketListQuery, SQLiteHistoryRepository
from backend.app.services.history_service import HistoryService
from backend.app.services.incident_correlation import IncidentCorrelationEngine
from backend.app.services.sniffer_detection_pipeline import SnifferDetectionPipeline
from backend.app.services.sniffer_service import SnifferService, CaptureStopUnavailableError
from backend.app.services.service_attribution import ServiceAttributionEngine
from backend.app.services.stability_recorder import StabilityRecorder
from core.capture.process_session import ProcessCaptureSession
from core.display_filter import apply_display_filter
from core.ids_ml import MLIDS
from core.netbotpro_sniffer_core.raw_buffer import RawBuffer, CaptureReadError, raise_reader_failure
from core.netbotpro_sniffer_core.pcap_session import PcapBinding
from core.netbotpro_sniffer_core.runtime import NetSniffer


def signal(second=0, **changes):
    return {'incident_type': 'possible_beaconing',
            'timestamp': f'2026-11-08T12:00:{second:02d}+00:00',
            'source_host': '10.0.0.5', 'destination_host': '8.8.8.8',
            'flow_key': 'flow-a', 'source': 'flow', 'severity': 'low',
            'application': 'app-a', 'domain': 'a.example', **changes}


class AuditCorrectionsTests(unittest.TestCase):
    def test_native_error_details_are_preserved_after_raw_queue_drains(self):
        reader = Mock()
        reader.next.side_effect = [(1., b'frame'), OSError(6, 'adapter removed')]
        reader.wire_length = 5
        buffer = RawBuffer(reader, sampler=lambda handle: (0, 0, 0))
        buffer._thread.join(2)
        self.assertFalse(buffer._thread.is_alive())
        self.assertEqual(buffer.next(), (1., b'frame'))
        with self.assertRaisesRegex(CaptureReadError, 'adapter removed'):
            buffer.next()
        self.assertTrue(buffer.snapshot()['error_recoverable'])
        reader.close.assert_called_once()

    def test_unknown_reader_error_is_not_silently_recoverable(self):
        with self.assertRaises(RuntimeError):
            raise_reader_failure({'error': 'ValueError', 'error_recoverable': False})
        binding = PcapBinding.__new__(PcapBinding)
        reader = Mock()
        reader.snapshot.return_value = {'error': 'OSError', 'error_detail': 'adapter gone', 'error_recoverable': True}
        binding._sockets = [(Mock(raw_reader=reader), 1, 'adapter')]
        with self.assertRaises(CaptureReadError):
            binding.is_closed()

    def test_native_loop_rebinds_only_recoverable_errors_and_keeps_manual_pin(self):
        for automatic, failure, opens in ((True, CaptureReadError('gone'), 2),
                                           (True, CaptureReadError('repeated disappearance'), 4),
                                           (False, CaptureReadError('gone'), 1),
                                           (True, RuntimeError('decoder bug'), 1)):
            with self.subTest(automatic=automatic, failure=type(failure).__name__):
                sniffer = NetSniffer(lambda packet: None)
                sniffer._running = True
                sniffer._auto_interface = automatic
                sniffer._iface = 'adapter'
                bindings = []
                def create(*args):
                    binding = Mock()
                    binding.matches.return_value = True
                    binding.sniff_arguments.return_value = {}
                    binding.raw_status.return_value = []
                    binding.is_closed.side_effect = failure if opens == 1 or len(bindings) < opens - 1 else None
                    if opens > 1 and len(bindings) == opens - 1:
                        binding.is_closed.return_value = False
                    bindings.append(binding)
                    return binding
                def sniff(**kwargs):
                    if opens > 1 and len(bindings) == opens:
                        sniffer._stop_event.set()
                sniff.__module__ = 'scapy.test_fixture'
                sniffer._sniff_func = sniff
                probe = Mock()
                probe.take.return_value = ('adapter', 'adapter', None, '')
                with patch('core.netbotpro_sniffer_core.runtime.RouteProbe', return_value=probe), \
                     patch('core.netbotpro_sniffer_core.runtime.PcapBinding', side_effect=create), \
                     patch.object(sniffer, '_packet_builder', return_value=Mock()):
                    sniffer._sniff_loop('adapter')
                self.assertEqual(len(bindings), opens)
                for binding in bindings:
                    binding.drain.assert_called_once()
                    binding.close.assert_called_once()
                self.assertEqual(bool(sniffer._last_error), opens == 1)

    def test_parent_retains_specific_failure_when_producer_exits(self):
        session = ProcessCaptureSession(lambda packet: None)
        session._journal = Mock()
        session._journal.first.return_value = None
        session._process = Mock()
        session._process.is_alive.return_value = False
        session._stopping = threading.Event()
        session._error = 'specific driver failure'
        session._read_errors = Mock()
        session._receive_journal()
        self.assertEqual(session._error, 'specific driver failure')
        session._read_errors.assert_called_once()

    def test_failed_capture_can_exit_only_when_closed_and_drained(self):
        session = ProcessCaptureSession(lambda packet: None, journal_path='unused')
        session._process = Mock()
        session._process.is_alive.return_value = False
        session._closed = True
        session._complete.set()
        session.capture_status = Mock(return_value={'ipc_pending': 0, 'journal_pending_records': 0})
        self.assertTrue(session.shutdown_ready())
        session.capture_status.return_value['journal_pending_records'] = 1
        self.assertFalse(session.shutdown_ready())
        session.capture_status.return_value['journal_pending_records'] = 0
        session._closed = False
        self.assertFalse(session.shutdown_ready())

    def test_exit_preserves_failure_without_ignoring_pending_work(self):
        for drained in (True, False):
            service = SnifferService.__new__(SnifferService)
            service._lock = threading.RLock()
            service._lifecycle_lock = threading.RLock()
            engine = ProcessCaptureSession(lambda row: None)
            engine.stop = Mock(side_effect=RuntimeError('driver failed'))
            engine.shutdown_ready = Mock(return_value=drained)
            engine.capture_status = Mock(return_value={'running': False, 'health': 'critical', 'capture_error': 'driver failed'})
            service._engine = engine
            service.drain_packet_queue = Mock(return_value=True)
            service._publisher = Mock()
            service.get_state = Mock(return_value={'running': False})
            service._persistence = Mock()
            service._persistence.flush.return_value = True
            if drained:
                self.assertTrue(service.prepare_exit()['exit_prepared'])
                self.assertEqual(service._capture_runtime_state()['capture_error'], 'driver failed')
            else:
                with self.assertRaises(CaptureStopUnavailableError):
                    service.prepare_exit()
                service._persistence.flush.assert_not_called()

    def test_filter_typed_zero_false_and_dns_aliases(self):
        row = {'proto': 'TCP', 'flags': 16, 'dns_rcode': 0, 'dns_qname': 'a.example'}
        for expression in ('dns.rcode == 0', 'tcp.flags.syn == false', 'tcp.flags.ack == true', 'dns.qry.name == a.example'):
            self.assertEqual(apply_display_filter([row], expression), [row])
        self.assertEqual(apply_display_filter([row], 'dns.rcode != 0'), [])
        self.assertEqual(apply_display_filter([{'dns_query': 'a.example'}], 'dns.qry.name == a.example'), [{'dns_query': 'a.example'}])

    def test_protocol_qualified_fields_do_not_match_other_transports(self):
        row = {'proto': 'UDP', 'dport': 443, 'flags': 'S'}
        for expression in ('tcp.port == 443', 'tcp.flags.syn == true', 'tcp.flags.syn == false'):
            self.assertEqual(apply_display_filter([row], expression), [])
        self.assertEqual(apply_display_filter([row], 'udp.port == 443'), [row])

    def test_protocol_and_display_filters_precede_counting_and_pagination(self):
        class Rows:
            def recent_packets(self):
                return [{'id': i, 'proto': 'TCP', 'app_protocol': app} for i, app in enumerate(('HTTP', 'HTTP', 'TLS', 'TLS'))]
        memory = MemoryHistoryRepository(Rows())
        query = PacketListQuery.from_raw({'display_filter': 'app_protocol == TLS', 'limit': 1, 'offset': 1})
        result = memory.list_packets(query)
        self.assertEqual(result['total'], 2)
        self.assertEqual(result['items'][0]['id'], 3)
        self.assertEqual(memory.list_packets(PacketListQuery(proto='TLS'))['total'], 2)
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / 'packets.db')
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE packets (id INTEGER PRIMARY KEY, proto TEXT, app_protocol TEXT)')
                db.executemany('INSERT INTO packets VALUES (?, ?, ?)', [(i, 'TCP', app) for i, app in enumerate(('HTTP', 'HTTP', 'TLS', 'TLS'))])
                db.commit()
            repository = SQLiteHistoryRepository(db_path=path)
            for response in (repository.list_packets(query), asyncio.run(repository.alist_packets(query))):
                self.assertEqual(response['total'], 2)
                self.assertEqual(len(response['items']), 1)
                self.assertEqual(response['items'][0]['id'], 2)
            self.assertEqual(repository.list_packets(PacketListQuery(proto='TLS'))['total'], 2)

    def test_cache_detaches_results_and_generation_invalidates_inflight_writes(self):
        class Rows:
            def recent_packets(self):
                return [{'id': 1, 'src': '10.0.0.5', 'dst': '8.8.8.8', 'proto': 'TCP'}]
        service = HistoryService(Rows(), sqlite_repository=object())
        with patch('backend.app.services.history_service.is_persist_enabled', return_value=False):
            result = service.get_packets({})
            result['items'][0]['id'] = 99
            self.assertEqual(service.get_packets({})['items'][0]['id'], 1)
            query = PacketListQuery.from_raw({})
            old_key = service._make_cache_key('packets_list', query)
            service.invalidate()
            service._write_cache(service._list_cache, old_key, result, max_entries=48, ttl_sec=1)
            self.assertNotEqual(old_key, service._make_cache_key('packets_list', query))
            self.assertEqual(service.get_packets({})['items'][0]['id'], 1)

    def test_unknown_encryption_is_not_periodicity_and_local_is_not_external(self):
        classify = IncidentCorrelationEngine._classify
        packet = {'service_unknown': True, 'src': '10.0.0.5', 'dst': '8.8.8.8'}
        self.assertEqual(classify('', packet, {'app_protocol': 'TLS'}), 'unusual_external_service')
        for source, dest in (('10.0.0.5', '10.0.0.1'), ('fd00::1', 'fd00::2'), ('fe80::1', 'ff02::16')):
            self.assertEqual(classify('', {**packet, 'src': source, 'dst': dest, 'direction': 'LOCAL'}, {}), '')
        self.assertEqual(classify('Periodic connection observed', packet, {}), 'possible_beaconing')

    def test_unrelated_peer_and_application_do_not_merge_but_scans_can_span_peers(self):
        for kind, expected in (('possible_beaconing', 2), ('possible_port_scan', 1)):
            engine = IncidentCorrelationEngine()
            for second in range(3):
                engine.ingest_signal(signal(second, incident_type=kind))
            for second in range(3, 6):
                engine.ingest_signal(signal(second, incident_type=kind, destination_host='8.8.4.4', flow_key='flow-b', domain='b.example', application='app-b'))
            self.assertEqual(len(engine._incidents), expected)

    def test_late_evidence_updates_first_seen_and_duplicate_ids_are_bounded(self):
        engine = IncidentCorrelationEngine()
        for second in range(3):
            engine.ingest_signal(signal(second))
        result = engine.ingest_signal(signal(timestamp='2026-11-08T11:59:59+00:00', signal_id='stable-observation'))
        self.assertEqual(result['first_seen'], '2026-11-08T11:59:59+00:00')
        engine.ingest_signal(signal(signal_id='stable-observation'))
        self.assertEqual(next(iter(engine._incidents.values()))['signal_count'], 4)
        self.assertEqual(engine.metrics()['duplicate_signals_total'], 1)
        engine.reset()
        self.assertFalse(engine._seen_signal_ids)

    def test_ml_scoring_failure_is_visible_to_pipeline_and_model_stats(self):
        ml = MLIDS()
        pipeline = SnifferDetectionPipeline(ids_ml=ml, rule_engine=Mock(analyze=Mock(return_value=None)), settings_provider=lambda: {'ids_signature_enabled': False})
        with patch.object(ml, '_prepare_packet_locked', return_value=(object(), [1.])), \
             patch.object(ml, '_cached_model_score', side_effect=RuntimeError('score failed')):
            pipeline.analyze({'src': '10.0.0.5', 'dst': '8.8.8.8', 'proto': 'TCP'})
        self.assertEqual(pipeline.health_stats()['errors_by_detector']['ml'], 1)
        self.assertEqual(pipeline.health_stats()['health'], 'degraded')
        self.assertEqual(ml.training_stats()['scoring_errors_total'], 1)

    def test_dns_ttl_overrides_flat_answer_fallback_and_expires_at_boundary(self):
        engine = ServiceAttributionEngine()
        answer = {'src': '10.0.0.1', 'dst': '10.0.0.5', 'sport': 53,
                  'dns_qname': 'a.example', 'ts': '2026-11-08T12:00:00Z',
                  'dns_answer_ips': ['8.8.8.8'], 'dns_answers': [{'ip': '8.8.8.8', 'ttl': 1}]}
        engine._observe_dns(answer)
        request = {'src': '10.0.0.5', 'dst': '8.8.8.8', 'remote_ip': '8.8.8.8', 'ts': answer['ts']}
        self.assertEqual(engine._destination_domain(request)[0], 'a.example')
        request['ts'] = '2026-11-08T12:00:01Z'
        self.assertEqual(engine._destination_domain(request)[0], '')

    def test_dns_zero_ttl_invalidates_previous_name_without_cross_client_leak(self):
        engine = ServiceAttributionEngine()
        answer = {'src': '10.0.0.1', 'dst': '10.0.0.5', 'sport': 53,
                  'dns_qname': 'a.example', 'ts': '2026-11-08T12:00:00Z', 'dns_answer_ips': ['8.8.8.8']}
        engine._observe_dns(answer)
        request = {'src': '10.0.0.6', 'dst': '8.8.8.8', 'ts': answer['ts']}
        self.assertEqual(engine._destination_domain(request)[0], '')
        engine._observe_dns({**answer, 'dns_answers': [{'ip': '8.8.8.8', 'ttl': 0}]})
        self.assertEqual(engine._destination_domain({**request, 'src': '10.0.0.5'})[0], '')

    def test_recorder_does_not_offer_ready_with_stale_counters_or_backlog(self):
        for stale, backlog in ((True, False), (False, True)):
            snapshot = {'capture': {'running': True, 'capture_started_at': 1,
                'ipc_pending': 20000 if backlog else 0, 'journal_backlog_warning_records': 8192,
                'driver_stats': {'available': True, 'coverage_complete': True,
                                 'sample_age_seconds': 50 if stale else 0}}}
            ticks = iter((0., 1.))
            with tempfile.TemporaryDirectory() as folder:
                recorder = StabilityRecorder(lambda: snapshot, Path(folder) / 'sample.jsonl',
                    interval=1, clock=lambda: next(ticks), resources=lambda pid: {'backend_rss_bytes': 1, 'capture_rss_bytes': 1})
                recorder._summary['target_seconds'] = 1
                recorder.sample()
                recorder.sample()
                self.assertNotEqual(recorder.stats()['assessment'], 'ready_for_review')
                if backlog:
                    self.assertEqual(recorder.stats()['health'], 'degraded')


if __name__ == '__main__':
    unittest.main()
