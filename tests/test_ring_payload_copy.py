import unittest
from backend.app.services.live_ring_buffer import _without_raw_payload


class PayloadCopyTests(unittest.TestCase):
    def test_nested_containers_are_detached_and_raw_payload_is_removed(self):
        original = {'payload_hex':'secret','sample':[{'payload_ascii':'secret','count':0,'ok':False,'name':'TLS'}, ('a', None)]}
        result = _without_raw_payload(original)
        self.assertEqual(result['payload_hex'], '')
        self.assertEqual(result['sample'][0], {'payload_ascii':'','count':0,'ok':False,'name':'TLS'})
        result['sample'][0]['name'] = 'changed'
        self.assertEqual(original['sample'][0]['name'], 'TLS')
        self.assertEqual(result['sample'][1], ['a',None])
