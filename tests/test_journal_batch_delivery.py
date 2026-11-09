import ast
from pathlib import Path
import unittest

from core.capture.batch_delivery import BatchDeliveryError, JournalBatchDelivery


class JournalBatchDeliveryTests(unittest.TestCase):
    def test_prepare_callbacks_accounting_then_acknowledgement(self):
        events = []
        packets = [{'sequence': 1}, {'sequence': 2}]
        delivery = JournalBatchDelivery(
            lambda packet: events.append(('packet', packet)),
            lambda identifier: events.append(('ack', identifier)),
            prepare=lambda batch: events.append(('prepare', batch)),
            on_completed=lambda: events.append(('complete', None)))
        receipt = delivery.deliver(17, packets)
        self.assertEqual(events, [('prepare', packets), ('packet', packets[0]),
            ('complete', None), ('packet', packets[1]), ('complete', None), ('ack', 17)])
        self.assertIs(events[0][1], packets)
        self.assertIs(events[1][1], packets[0])
        self.assertEqual((receipt.identifier, receipt.completed_records), (17, 2))

    def test_failure_at_each_stage_never_retries_or_acknowledges_early(self):
        for failing in ('preparation', 'analysis', 'acknowledgement'):
            with self.subTest(stage=failing):
                events = []
                cause = ValueError('private packet contents must not appear in error text')
                def prepare(batch):
                    events.append('prepare')
                    if failing == 'preparation':
                        raise cause
                def callback(packet):
                    events.append(packet['sequence'])
                    if failing == 'analysis' and packet['sequence'] == 2:
                        raise cause
                def acknowledge(identifier):
                    events.append('ack')
                    if failing == 'acknowledgement':
                        raise cause
                delivery = JournalBatchDelivery(callback, acknowledge, prepare=prepare,
                    on_completed=lambda: events.append('complete'))
                with self.assertRaises(BatchDeliveryError) as raised:
                    delivery.deliver(1, [{'sequence': 1}, {'sequence': 2}, {'sequence': 3}])
                error = raised.exception
                self.assertEqual(error.stage, failing)
                self.assertIs(error.__cause__, cause)
                self.assertNotIn('private packet', str(error))
                self.assertIn('acknowledgement unconfirmed' if failing == 'acknowledgement'
                    else 'batch retained', str(error))
                expected = {'preparation': ['prepare'],
                    'analysis': ['prepare', 1, 'complete', 2],
                    'acknowledgement': ['prepare', 1, 'complete', 2, 'complete', 3, 'complete', 'ack']}
                self.assertEqual(events, expected[failing])
                self.assertEqual(error.completed_records,
                    {'preparation': 0, 'analysis': 1, 'acknowledgement': 3}[failing])

    def test_completion_observer_failure_does_not_acknowledge(self):
        acknowledged = []
        def fail():
            raise RuntimeError('counter failure')
        delivery = JournalBatchDelivery(lambda packet: None, acknowledged.append, on_completed=fail)
        with self.assertRaises(BatchDeliveryError) as raised:
            delivery.deliver(1, [{}])
        self.assertEqual(raised.exception.completed_records, 1)
        self.assertEqual(acknowledged, [])

    def test_empty_batch_preserves_legacy_acknowledgement(self):
        events = []
        delivery = JournalBatchDelivery(lambda packet: self.fail('unexpected packet'), events.append,
            on_completed=lambda: self.fail('unexpected completion'))
        self.assertEqual(delivery.deliver(5, []).completed_records, 0)
        self.assertEqual(events, [5])

    def test_partial_failure_has_no_implicit_resume_or_exactly_once_claim(self):
        calls, acknowledged = [], []
        fail = True
        def callback(packet):
            calls.append(packet['sequence'])
            if fail and packet['sequence'] == 2:
                raise ValueError('stop')
        delivery = JournalBatchDelivery(callback, acknowledged.append, on_completed=lambda: None)
        packets = [{'sequence': 1}, {'sequence': 2}]
        with self.assertRaises(BatchDeliveryError):
            delivery.deliver(8, packets)
        self.assertEqual(acknowledged, [])
        fail = False
        delivery.deliver(8, packets)
        self.assertEqual(calls, [1, 2, 1, 2])
        self.assertEqual(acknowledged, [8])

    def test_no_lifecycle_storage_or_analysis_imports(self):
        import core.capture.batch_delivery as module
        tree = ast.parse(Path(module.__file__).read_text(encoding='utf-8'))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or '')
        self.assertEqual(set(imports), {'__future__', 'dataclasses', 'typing'})
