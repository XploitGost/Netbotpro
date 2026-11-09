import os
from pathlib import Path
import tempfile
import unittest

from core.capture.journal import CaptureJournal, JournalFull, _dpapi_functions, _protect
from core.capture.batch_delivery import BatchDeliveryError, JournalBatchDelivery


@unittest.skipUnless(os.name == 'nt', 'DPAPI journal requires Windows')
class JournalTests(unittest.TestCase):
    def test_partial_callback_failure_retains_complete_encrypted_batch_for_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'capture.db'
            journal = CaptureJournal(path)
            packets = [{'sequence': 1}, {'sequence': 2}, {'sequence': 3}]
            journal.append(packets)
            identifier, pending = journal.first()
            def callback(packet):
                if packet['sequence'] == 2:
                    raise ValueError('analysis failed')
            delivery = JournalBatchDelivery(callback, journal.acknowledge, on_completed=lambda: None)
            with self.assertRaises(BatchDeliveryError) as raised:
                delivery.deliver(identifier, pending)
            self.assertEqual(raised.exception.completed_records, 1)
            self.assertEqual(journal.stats()['journal_pending_records'], 3)
            journal.close()
            recovered = CaptureJournal(path)
            self.assertEqual(recovered.first(), (identifier, packets))
            delivered = []
            receipt = JournalBatchDelivery(delivered.append, recovered.acknowledge,
                on_completed=lambda: None).deliver(*recovered.first())
            self.assertEqual(delivered, packets)
            self.assertEqual(receipt.completed_records, 3)
            self.assertIsNone(recovered.first())
            recovered.close()

    def test_dpapi_bindings_reused_and_binary_roundtrip(self):
        first = _dpapi_functions()
        for data in (b'', b'\x00\xffprivate\x00', bytes(range(256))):
            encrypted = _protect(data)
            self.assertNotEqual(encrypted, data)
            self.assertEqual(_protect(encrypted, decrypt=True), data)
            self.assertIs(_dpapi_functions(), first)

    def test_encrypted_reopen_order_and_acknowledgement(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'capture.db'
            journal = CaptureJournal(path)
            journal.append([{'sequence':0, 'token':'never-plaintext-secret'}])
            journal.append([{'sequence':1}])
            self.assertEqual(journal.stats()['journal_pending_records'], 2)
            journal.close()
            for file in Path(folder).iterdir():
                self.assertNotIn(b'never-plaintext-secret', file.read_bytes())
            recovered = CaptureJournal(path)
            first = recovered.first()
            self.assertEqual(first[1][0]['token'], 'never-plaintext-secret')
            recovered.acknowledge(first[0])
            recovered.acknowledge(first[0])
            self.assertEqual(recovered.first()[1][0]['sequence'], 1)
            recovered.acknowledge(recovered.first()[0])
            self.assertEqual(recovered.stats()['journal_pending_records'], 0)
            self.assertEqual(recovered.stats()['journal_pending_bytes'], 0)
            recovered.close()

    def test_full_journal_rejects_without_deleting_old_data(self):
        with tempfile.TemporaryDirectory() as folder:
            journal = CaptureJournal(Path(folder)/'capture.db')
            journal.append([{'sequence':0}])
            before = journal.stats()
            journal.max_bytes = before['journal_pending_bytes']
            with self.assertRaises(JournalFull):
                journal.append([{'sequence':1}])
            self.assertEqual(journal.stats(), dict(before, journal_max_payload_bytes=journal.max_bytes))
            self.assertEqual(journal.first()[1], [{'sequence':0}])
            journal.close()
