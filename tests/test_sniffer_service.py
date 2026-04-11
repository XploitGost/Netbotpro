import unittest

from backend.app.services.event_bus import EventBus
from backend.app.services.sniffer_service import SnifferService


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
                return {"provider": "fake", "ready": True}

        return _Report()


class SnifferServiceTests(unittest.TestCase):
    def test_start_uses_injected_capture_provider(self):
        provider = _FakeCaptureProvider()
        service = SnifferService(EventBus(), capture_provider=provider)

        state = service.start("eth0")

        self.assertTrue(state["running"])
        self.assertEqual(provider.session.started_with, "eth0")
        self.assertEqual(state["iface"], "Ethernet")
        service.close()

    def test_capture_interfaces_include_preflight(self):
        provider = _FakeCaptureProvider()
        service = SnifferService(EventBus(), capture_provider=provider)

        payload = service.capture_interfaces()

        self.assertEqual(payload["recommended"], "eth0")
        self.assertEqual(payload["preflight"]["provider"], "fake")


if __name__ == "__main__":
    unittest.main()
