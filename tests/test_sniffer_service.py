import unittest
from unittest.mock import patch

from backend.app.services.event_bus import EventBus
from backend.app.services.sniffer_service import CaptureStartUnavailableError, SnifferService


class _FakeCaptureSession:
    def __init__(self) -> None:
        self.started_with = None
        self.stopped = False

    def start(self, iface=None) -> None:
        self.started_with = iface

    def stop(self) -> None:
        self.stopped = True

    def selected_iface(self) -> str | None:
        return self.started_with or "eth0"


class _FakeCaptureProvider:
    name = "fake"

    def __init__(self) -> None:
        self.session = _FakeCaptureSession()

    def create_session(self, packet_callback):
        self.packet_callback = packet_callback
        return self.session

    def list_interfaces(self):
        return {"recommended": "eth0", "recommended_label": "Ethernet", "items": [{"value": "eth0", "name": "Ethernet"}]}

    def describe_interface(self, candidate):
        return "Ethernet"

    def resolve_interface(self, candidate):
        return candidate

    def preflight(self):
        class _Report:
            @staticmethod
            def to_dict():
                return {
                    "provider": "fake",
                    "ready": True,
                    "recommended_interface": "eth0",
                    "checks": [{"code": "interfaces_available", "ok": True, "severity": "error", "detail": "ok"}],
                }

        return _Report()


class _UnavailableCaptureProvider(_FakeCaptureProvider):
    def create_session(self, packet_callback):
        raise AssertionError("create_session should not be called when preflight is not ready")

    def preflight(self):
        class _Report:
            @staticmethod
            def to_dict():
                return {
                    "provider": "fake",
                    "ready": False,
                    "checks": [{"code": "interfaces_available", "ok": False, "severity": "error", "detail": "Detected 0 capture interface(s)."}],
                }

        return _Report()


class _SlowCaptureProvider(_FakeCaptureProvider):
    def create_session(self, packet_callback):
        __import__("time").sleep(0.2)
        return super().create_session(packet_callback)


class _FakeFlowService:
    def __init__(self) -> None:
        self.ingested = []

    def ingest(self, packet, alerts):
        self.ingested.append((packet, alerts))

    def reset(self):
        self.ingested.clear()


class SnifferServiceTests(unittest.TestCase):
    def test_start_uses_injected_capture_provider(self):
        provider = _FakeCaptureProvider()
        service = SnifferService(EventBus(), capture_provider=provider)

        state = service.start("eth0")

        self.assertTrue(state["running"])
        self.assertEqual(provider.session.started_with, "eth0")
        self.assertEqual(state["iface"], "Ethernet")
        service.close()

    def test_start_without_iface_uses_preflight_recommended_interface(self):
        provider = _FakeCaptureProvider()
        service = SnifferService(EventBus(), capture_provider=provider)

        state = service.start()

        self.assertTrue(state["running"])
        self.assertEqual(provider.session.started_with, "eth0")
        service.close()

    def test_capture_interfaces_include_preflight(self):
        provider = _FakeCaptureProvider()
        service = SnifferService(EventBus(), capture_provider=provider)

        payload = service.capture_interfaces()

        self.assertEqual(payload["recommended"], "eth0")
        self.assertEqual(payload["preflight"]["provider"], "fake")

    def test_start_fails_fast_when_preflight_is_not_ready(self):
        service = SnifferService(EventBus(), capture_provider=_UnavailableCaptureProvider())

        with self.assertRaises(CaptureStartUnavailableError) as ctx:
            service.start("iface=default")

        self.assertIn("Detected 0 capture interface", str(ctx.exception))

    def test_start_rejects_unknown_remote_interface_name(self):
        service = SnifferService(EventBus(), capture_provider=_FakeCaptureProvider())

        with self.assertRaises(CaptureStartUnavailableError) as ctx:
            service.start("not-a-local-interface")

        self.assertIn("local interfaces", str(ctx.exception))
        service.close()

    @patch("backend.app.services.sniffer_service.get_settings_snapshot", return_value={"payload_capture_enabled": False, "alert_only_mode": False})
    def test_payload_preview_is_removed_by_default_before_state_and_persistence(self, _mock_settings):
        service = SnifferService(
            EventBus(),
            capture_provider=_FakeCaptureProvider(),
            flow_service=_FakeFlowService(),
        )
        try:
            service._on_packet(
                {
                    "src": "192.168.1.10",
                    "dst": "8.8.8.8",
                    "proto": "TCP",
                    "payload_len": 42,
                    "payload_hex": "41 42",
                    "payload_ascii": "Authorization: Bearer secret",
                }
            )
            self.assertTrue(service.drain_packet_queue(timeout_sec=1.0))
            packet = service.recent_packets()[0]
        finally:
            service.close()

        self.assertEqual(packet["payload_len"], 42)
        self.assertEqual(packet["payload_hex"], "")
        self.assertEqual(packet["payload_ascii"], "")

    def test_alerts_are_linked_to_packet_flow_id(self):
        service = SnifferService(
            EventBus(),
            capture_provider=_FakeCaptureProvider(),
            flow_service=_FakeFlowService(),
        )
        packet = {
            "id": "pkt-1",
            "src": "192.168.1.10",
            "dst": "8.8.8.8",
            "sport": 50000,
            "dport": 443,
            "proto": "TCP",
        }

        alerts = service._assign_alert_ids(packet, [{"attack_type": "qa"}])

        self.assertEqual(alerts[0]["packet_id"], "pkt-1")
        self.assertTrue(str(alerts[0]["flow_id"]).startswith("flow-"))
        service.close()

    def test_start_times_out_when_capture_session_creation_hangs(self):
        service = SnifferService(EventBus(), capture_provider=_SlowCaptureProvider())

        with patch("backend.app.services.sniffer_service.CAPTURE_START_TIMEOUT_SEC", 0.01):
            with self.assertRaises(CaptureStartUnavailableError) as ctx:
                service.start("eth0")

        self.assertIn("timed out", str(ctx.exception).lower())
        service.close()

    def test_malformed_packet_does_not_stop_queue_worker(self):
        service = SnifferService(
            EventBus(),
            capture_provider=_FakeCaptureProvider(),
            flow_service=_FakeFlowService(),
        )
        try:
            service._on_packet({"src": object(), "dst": None, "proto": "TCP"})
            self.assertTrue(service.drain_packet_queue(timeout_sec=1.0))
            stats = service.packet_queue_stats()
        finally:
            service.close()

        self.assertTrue(stats["worker_alive"])
        self.assertEqual(stats["accepted_total"], 1)

    def test_close_stops_packet_queue_worker_cleanly(self):
        service = SnifferService(
            EventBus(),
            capture_provider=_FakeCaptureProvider(),
            flow_service=_FakeFlowService(),
        )

        service._on_packet({"src": "1.1.1.1", "dst": "2.2.2.2", "proto": "TCP"})
        service.close()

        self.assertFalse(service._packet_worker.is_alive())


if __name__ == "__main__":
    unittest.main()
