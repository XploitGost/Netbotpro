import threading
import multiprocessing as mp
import os
import tempfile
from pathlib import Path
import time
import unittest
from unittest.mock import Mock
from core.capture.process_session import ProcessCaptureSession


class FakeCapture:
    def __init__(self, callback):
        self.callback = callback
        self.running = False
    def start(self, iface=None):
        self.iface = iface
        self.running = True
        for i in range(40):
            self.callback({'sequence': i, 'src': '192.0.2.1'})
    def stop(self):
        self.running = False
    def selected_iface(self):
        return self.iface
    def capture_status(self):
        return {'running': self.running}


class FailedCapture(FakeCapture):
    def start(self, iface=None):
        raise RuntimeError('test driver failure')


class FinalPacketCapture(FakeCapture):
    def stop(self):
        self.callback({'sequence':40})
        self.running = False


class MovingCapture(FakeCapture):
    def capture_status(self):
        return dict(running=self.running, selected_iface='ras:amir',
                    auto_interface=True, route_switches=1, route_warning='')


class CrashedCapture(FakeCapture):
    def capture_status(self):
        return {'running': False, 'capture_error': 'test driver crash'}


def orphan_parent(channel):
    session = ProcessCaptureSession(lambda p: None, factory=FakeCapture, capacity=100)
    session.start()
    channel.send(session._process.pid)
    channel.close()
    os._exit(0)


class ProcessCaptureTests(unittest.TestCase):
    def test_journal_failure_stage_and_completed_prefix_are_preserved(self):
        for stage in ('preparation', 'analysis', 'acknowledgement'):
            with self.subTest(stage=stage):
                def callback(packet):
                    if stage == 'analysis' and packet['sequence'] == 2:
                        raise ValueError('test failure')
                session = ProcessCaptureSession(callback)
                session._journal = Mock()
                session._journal.first.return_value = (7, [{'sequence': 1}, {'sequence': 2}])
                session._stopping = threading.Event()
                if stage == 'preparation':
                    session._prepare_batch = Mock(side_effect=ValueError('test failure'))
                if stage == 'acknowledgement':
                    session._journal.acknowledge.side_effect = ValueError('test failure')
                session._receive_journal()
                self.assertTrue(session._stopping.is_set())
                self.assertEqual(session._journal_failure_stage, stage)
                self.assertEqual(session._journal_acknowledged, 0)
                self.assertEqual(session._callback_errors, 1)
                self.assertEqual(session._delivered,
                    {'preparation': 0, 'analysis': 1, 'acknowledgement': 2}[stage])
                self.assertIn(f'Journal {stage} failed', session._error)
                self.assertEqual(session._journal.first.call_count, 1)
                self.assertEqual(session._journal.acknowledge.call_count,
                    1 if stage == 'acknowledgement' else 0)

    @unittest.skipUnless(os.name == 'nt', 'DPAPI journal requires Windows')
    def test_inflight_packet_finishes_during_normal_journal_stop(self):
        with tempfile.TemporaryDirectory() as folder:
            received = []
            session = ProcessCaptureSession(received.append, factory=FinalPacketCapture,
                journal_path=Path(folder)/'capture.db')
            session.start()
            session.stop()
            status = session.capture_status()
            self.assertEqual(status['ipc_received'], 41)
            self.assertEqual(status['ipc_accepted'], 41)
            self.assertEqual(status['ipc_delivered'], 41)
            self.assertEqual(status['ipc_dropped'], 0)
            self.assertEqual([item['sequence'] for item in received], list(range(41)))

    def test_control_updates_do_not_require_public_status_polling(self):
        session = ProcessCaptureSession(lambda packet: None, factory=MovingCapture)
        session.start('Wi-Fi')
        try:
            deadline = time.monotonic()+5
            while time.monotonic() < deadline:
                with session._lock:
                    selected = session._route_state.get('selected_iface')
                if selected == 'ras:amir':
                    break
                time.sleep(.05)
            self.assertEqual(selected, 'ras:amir')
        finally:
            session.stop()
        self.assertFalse(session._control_reader.is_alive())

    def test_child_handover_updates_parent_without_resetting_delivery(self):
        received = []
        session = ProcessCaptureSession(received.append, factory=MovingCapture, capacity=100)
        session.start('Wi-Fi')
        try:
            deadline = time.monotonic() + 5
            while session.selected_iface() != 'ras:amir' and time.monotonic() < deadline:
                time.sleep(.05)
            status = session.capture_status()
            self.assertEqual(status['selected_iface'], 'ras:amir')
            self.assertEqual(status['route_switches'], 1)
            self.assertTrue(status['running'])
            self.assertEqual(status['capture_error'], '')
        finally:
            session.stop()
        self.assertEqual(len(received), 40)

    def test_final_commit_after_empty_read_is_drained(self):
        received = []
        session = ProcessCaptureSession(received.append)
        session._journal = Mock()
        session._journal.first.side_effect = [None, (1, [{'sequence':0}]), None, None]
        session._process = Mock()
        session._process.is_alive.return_value = False
        session._stopping = threading.Event()
        session._stopping.set()
        session._receive_journal()
        self.assertEqual(received, [{'sequence':0}])
        session._journal.acknowledge.assert_called_once_with(1)
        self.assertEqual(session._journal_acknowledged, 1)
        self.assertIsNone(session._journal_failure_stage)

    @unittest.skipUnless(os.name == 'nt', 'DPAPI journal requires Windows')
    def test_journal_drains_after_analysis_and_retains_failed_batch(self):
        from core.capture.journal import CaptureJournal
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'journal.db'
            received = []
            session = ProcessCaptureSession(received.append, factory=FakeCapture, journal_path=path)
            session.start()
            session.stop()
            self.assertEqual([p['sequence'] for p in received], list(range(40)))
            self.assertEqual(session.capture_status()['journal_pending_records'], 0)
            self.assertEqual(session.capture_status()['journal_acknowledged_records'], 40)
            def fail(packet):
                raise RuntimeError('analysis failure')
            failed = ProcessCaptureSession(fail, factory=FakeCapture, journal_path=path)
            failed.start()
            self.assertTrue(failed._complete.wait(5))
            with self.assertRaisesRegex(RuntimeError, 'batch retained'):
                failed.stop()
            recovered = CaptureJournal(path)
            self.assertGreater(recovered.stats()['journal_pending_records'], 0)
            recovered.close()

    def test_capture_child_exits_when_parent_dies_abruptly(self):
        import psutil
        context = mp.get_context('spawn')
        receiver, sender = context.Pipe(duplex=False)
        parent = context.Process(target=orphan_parent, args=(sender,))
        parent.start()
        sender.close()
        self.assertTrue(receiver.poll(10))
        pid = receiver.recv()
        receiver.close()
        parent.join(5)
        self.assertFalse(parent.is_alive())
        deadline = time.monotonic()+5
        while psutil.pid_exists(pid) and time.monotonic() < deadline:
            time.sleep(.1)
        self.assertFalse(psutil.pid_exists(pid), 'Orphan capture process survived')

    def test_spawn_preserves_order_and_drains_on_stop(self):
        received = []
        session = ProcessCaptureSession(received.append, factory=FakeCapture, capacity=100)
        session.start('fake-adapter')
        try:
            self.assertEqual(session.selected_iface(), 'fake-adapter')
        finally:
            session.stop()
        self.assertEqual([p['sequence'] for p in received], list(range(40)))
        status = session.capture_status()
        self.assertEqual(status['ipc_dropped'], 0)
        self.assertEqual(status['ipc_delivered'], 40)
        self.assertEqual(status['ipc_pending'], 0)
        self.assertFalse(session._process.is_alive())
        session.stop()

    def test_startup_error_is_not_reported_as_ready(self):
        session = ProcessCaptureSession(lambda p: None, factory=FailedCapture)
        with self.assertRaisesRegex(RuntimeError, 'test driver failure'):
            session.start()
        self.assertFalse(session._process.is_alive())

    def test_ipc_overflow_is_counted_not_hidden(self):
        gate = threading.Event()
        session = ProcessCaptureSession(lambda p: gate.wait(5), factory=FakeCapture, capacity=2)
        try:
            session.start()
            status = session.capture_status()
            self.assertEqual(status['ipc_received'], 40)
            self.assertGreater(status['ipc_dropped'], 0)
            self.assertLessEqual(status['ipc_pending'], 2)
            self.assertEqual(status['ipc_accepted'] + status['ipc_dropped'], 40)
        finally:
            gate.set()
            session.stop()
        self.assertEqual(session.capture_status()['ipc_delivered'], status['ipc_accepted'])

    def test_driver_exit_is_visible_and_stop_does_not_claim_success(self):
        session = ProcessCaptureSession(lambda p: None, factory=CrashedCapture, capacity=100)
        session.start()
        self.assertTrue(session._complete.wait(5))
        self.assertIn('test driver crash', session.capture_status()['capture_error'])
        with self.assertRaisesRegex(RuntimeError, 'test driver crash'):
            session.stop()
        self.assertFalse(session._process.is_alive())
