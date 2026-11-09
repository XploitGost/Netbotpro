import threading
import time
import unittest
from unittest.mock import Mock, patch

from core.netbotpro_sniffer_core.deferred_enrichment import DeferredLookup
from core.netbotpro_sniffer_core.runtime import NetSniffer


class DeferredEnrichmentTests(unittest.TestCase):
    def test_packet_callback_continues_while_geo_lookup_is_pending(self):
        entered, release = threading.Event(), threading.Event()
        def resolver(key):
            entered.set()
            release.wait(3)
            return {'country': 'test'}
        lookup = DeferredLookup(resolver, {})
        received = []
        sniffer = NetSniffer(received.append)
        sniffer._running = True
        sniffer._builder = Mock()
        sniffer._builder.build.side_effect = lambda packet: dict(geo=lookup.lookup('ip'))
        try:
            sniffer._handle_packet(object())
            self.assertTrue(entered.wait(1))
            for _ in range(127):
                sniffer._handle_packet(object())
            self.assertEqual(len(received), 128)
            self.assertEqual(sniffer._callback_failures, 0)
            self.assertTrue(all(item['geo'] == {} for item in received))
            self.assertFalse(release.is_set())
        finally:
            release.set()
            lookup.close()

    def ready(self, lookup, key, predicate):
        deadline = time.monotonic()+3
        while time.monotonic() < deadline:
            value = lookup.lookup(key)
            if predicate(value):
                return value
            time.sleep(.01)
        self.fail('Optional lookup did not complete')

    def test_blocked_optional_io_does_not_block_capture_lookup(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def resolver(key):
            calls.append(threading.current_thread().ident)
            entered.set()
            release.wait(3)
            return {'country': 'test'}
        lookup = DeferredLookup(resolver, {})
        try:
            self.assertEqual(lookup.lookup('ip'), {})
            self.assertTrue(entered.wait(1))
            for _ in range(100):
                self.assertEqual(lookup.lookup('ip'), {})
            self.assertFalse(release.is_set())
            self.assertEqual(lookup.stats()['scheduled'], 1)
            self.assertNotEqual(calls[0], threading.current_thread().ident)
            release.set()
            value = self.ready(lookup, 'ip', bool)
            value['country'] = 'changed'
            self.assertEqual(lookup.lookup('ip')['country'], 'test')
        finally:
            release.set()
            lookup.close()

    def test_bounded_queue_deduplicates_and_rejects_only_optional_requests(self):
        entered, release = threading.Event(), threading.Event()
        def resolver(key):
            entered.set()
            release.wait(3)
            return key
        lookup = DeferredLookup(resolver, None, queue_max=1, capacity=1)
        try:
            lookup.lookup('first')
            self.assertTrue(entered.wait(1))
            lookup.lookup('second')
            lookup.lookup('second')
            lookup.lookup('third')
            self.assertEqual(lookup.stats()['requests_pending'], 2)
            self.assertEqual(lookup.stats()['queue_depth'], 1)
            self.assertEqual(lookup.stats()['optional_requests_rejected'], 1)
            release.set()
            self.ready(lookup, 'second', lambda value: value == 'second')
            self.assertLessEqual(lookup.stats()['cache_entries'], 1)
        finally:
            release.set()
            lookup.close()

    def test_expired_process_result_is_not_reused_and_errors_are_cached(self):
        clock = [0]
        resolver = Mock(return_value={'pid': 1})
        lookup = DeferredLookup(resolver, {'pid': None}, ttl=.5, clock=lambda:clock[0])
        try:
            self.ready(lookup, 'flow', lambda value:value['pid'] == 1)
            clock[0] = 1
            resolver.return_value = {'pid': 2}
            self.assertIsNone(lookup.lookup('flow')['pid'])
            self.ready(lookup, 'flow', lambda value:value['pid'] == 2)
            resolver.side_effect = ValueError('private lookup detail')
            lookup.lookup('failed')
            deadline = time.monotonic()+2
            while lookup.stats()['lookup_errors'] == 0 and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(lookup.stats()['lookup_errors'], 1)
            self.assertEqual(lookup.lookup('failed'), {'pid':None})
            self.assertNotIn('private', str(lookup.stats()))
        finally:
            lookup.close()

    def test_disabled_and_closed_provider_does_not_start_work(self):
        resolver = Mock()
        lookup = DeferredLookup(resolver, None, enabled=False)
        self.assertIsNone(lookup.lookup('anything'))
        resolver.assert_not_called()
        self.assertIsNone(lookup._thread)
        lookup.close()
        lookup.enabled = True
        self.assertIsNone(lookup.lookup('anything'))
        self.assertEqual(lookup.stats()['scheduled'], 0)

    def test_runtime_reuses_owned_workers_on_rebind_and_preserves_injected_provider(self):
        injected = Mock()
        sniffer = NetSniffer(lambda packet: None, geoip_provider=injected)
        factory = Mock(side_effect=lambda *args, **kwargs: Mock())
        with patch('core.netbotpro_sniffer_core.runtime.default_deferred_provider', factory), \
                patch('core.netbotpro_sniffer_core.runtime.PacketLayers'), \
                patch('core.netbotpro_sniffer_core.runtime.PacketMetadataBuilder'):
            sniffer._packet_builder()
            sniffer._builder = None
            sniffer._packet_builder()
            self.assertEqual(factory.call_count, 2)
            self.assertIs(sniffer._geoip_provider, injected)
        owned = [sniffer._mac_vendor_provider, sniffer._process_mapper]
        sniffer._close_enrichment()
        for provider in owned:
            provider.close.assert_called_once()
        injected.close.assert_not_called()
