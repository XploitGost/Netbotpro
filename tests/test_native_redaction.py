import random
import sys
import unittest
from unittest.mock import patch

from core import privacy_redaction as privacy


@unittest.skipIf(privacy._native_redact is None, 'Optional native accelerator is not built')
class NativeRedactionTests(unittest.TestCase):
    def compare(self, value, empty_fields=frozenset()):
        expected = privacy._redact_sensitive_data(value, {}, empty_fields, {})
        actual = privacy._native_redact(value, privacy.redact_sensitive_text,
                                        privacy._redact_sensitive_data,
                                        privacy.SENSITIVE_KEYS, empty_fields,
                                        privacy.SENSITIVE_ASCII_FAST_RE.pattern)
        self.assertEqual(actual, expected)
        return actual

    def test_generated_metadata_matches_python_reference(self):
        rng = random.Random(7913)
        keys = ['src', 'payload_hex', 'TOKEN', 'Proxy-Authorization', 'password', 'nested', 'cookie', 'ordinary']
        leaves = [None, 42, 1.25, False, '', '192.0.2.1', 'Bearer private',
                  'password=secret', '/?access_token=private', 'normal TLS packet',
                  'authorization: private', 'نام دامنه', 'ſecret=private']
        def value(depth):
            if depth == 0 or rng.random() < .4:
                return rng.choice(leaves)
            if rng.random() < .5:
                return {rng.choice(keys):value(depth-1) for _ in range(rng.randrange(5))}
            items = [value(depth-1) for _ in range(rng.randrange(5))]
            return items if rng.random() < .5 else tuple(items)
        for _ in range(2000):
            self.compare(value(5), {'payload_hex'})

    def test_ascii_candidate_shortcut_matches_all_markers_and_case_variants(self):
        rng = random.Random(71)
        for marker in privacy.SENSITIVE_ASCII_FAST_RE.pattern.split('|'):
            for _ in range(40):
                mixed = ''.join(char.upper() if rng.randrange(2) else char for char in marker)
                self.compare({'text': 'prefix ' + mixed + '=private suffix'})
        for _ in range(500):
            self.compare(''.join(chr(rng.randrange(128)) for _ in range(100)))

    def test_candidate_rule_change_disables_native_shortcut(self):
        from unittest.mock import Mock
        text = Mock(return_value='replaced')
        result = privacy._native_redact('ordinary', text, privacy._redact_sensitive_data,
                                       privacy.SENSITIVE_KEYS, frozenset(), 'new-rule')
        self.assertEqual(result, 'replaced')
        text.assert_called_once_with('ordinary')

    def test_key_normalization_matches_reference_for_all_ascii_and_unicode_paths(self):
        for key in privacy.SENSITIVE_KEYS | {'payload_hex', 'src', 'length', ''}:
            for variant in (key, key.upper(), key.title(), key.replace('_', '-')):
                self.compare({variant: 'value', 'nested': [{variant: 'value'}]}, {'payload_hex'})
        for key in ('İTOKEN', 'ſecret', 'Key', 'نام', 'ＰＡＳＳＷＯＲＤ', 'cookie\x00',
                    'payload-hex', 'payload_HEX', 'set-cookie', 'Set-Cookie'):
            self.compare({key: 'value'}, {'payload_hex', 'payload-hex'})
        # Changing policy between calls must not reuse a previous classification.
        self.assertEqual(self.compare({'src': 'visible'}), {'src': 'visible'})
        self.assertEqual(self.compare({'src': 'hidden'}, {'src'}), {'src': ''})
        self.assertEqual(self.compare({'src': 'visible'}), {'src': 'visible'})

    def test_copies_and_subclasses_and_nonstring_keys(self):
        class SpecialDict(dict):
            pass
        class SpecialList(list):
            pass
        class SpecialString(str):
            pass
        source = dict(labels=['token=private'], other=SpecialDict(x=SpecialList([SpecialString('Bearer private')])))
        actual = self.compare(source)
        actual['labels'].append('mutation')
        self.assertEqual(source['labels'], ['token=private'])
        self.compare({1:'token=private', ('password',):'value'})

    def test_cycles_fail_and_callback_errors_propagate(self):
        cyclic = []
        cyclic.append(cyclic)
        with self.assertRaises(RecursionError):
            privacy._native_redact(cyclic, privacy.redact_sensitive_text,
                                   privacy._redact_sensitive_data, privacy.SENSITIVE_KEYS, frozenset())
        def fail(value):
            raise ValueError('test failure')
        with self.assertRaisesRegex(ValueError, 'test failure'):
            privacy._native_redact({'summary':'text'}, fail,
                                   privacy._redact_sensitive_data, privacy.SENSITIVE_KEYS, frozenset())

    def test_no_retained_packet_references_and_fallback(self):
        packet = {'summary':'Bearer private', 'nested':[1, 2, 3]}
        before = sys.getrefcount(packet)
        for _ in range(500):
            self.compare(packet)
        self.assertEqual(sys.getrefcount(packet), before)
        with patch.object(privacy, '_native_redact', None):
            self.assertEqual(privacy.redact_sensitive_data(packet),
                             privacy._redact_sensitive_data(packet, {}, frozenset(), {}))
