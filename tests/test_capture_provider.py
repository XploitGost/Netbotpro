import unittest
import subprocess
from unittest.mock import patch

from core.capture.system_provider import SystemCaptureProvider


class _PrivilegeChecker:
    def __init__(self, elevated: bool) -> None:
        self._elevated = elevated

    def is_elevated(self) -> bool:
        return self._elevated

    def detail(self, os_name: str) -> str:
        return f"privileges:{os_name}"


class CaptureProviderTests(unittest.TestCase):
    def test_preflight_reports_ready_on_supported_platform_with_interfaces(self):
        provider = SystemCaptureProvider(
            interfaces_func=lambda: {
                "recommended": "eth0",
                "recommended_label": "Ethernet",
                "items": [{"value": "eth0", "name": "Ethernet", "label": "Ethernet", "is_up": True, "recommended": True}],
            },
            privilege_checker=_PrivilegeChecker(elevated=False),
            os_name_getter=lambda: "linux",
            scapy_checker=lambda: (True, "ok"),
        )

        report = provider.preflight().to_dict()

        self.assertTrue(report["supported"])
        self.assertTrue(report["ready"])
        self.assertTrue(report["requires_elevation"])
        self.assertEqual(report["interface_count"], 1)
        self.assertEqual(report["recommended_interface"], "eth0")
        self.assertEqual(report["discovery_source"], "live")
        self.assertEqual(report["discovery_reason"], None)
        self.assertEqual(report["checks"][2]["code"], "interfaces_available")
        self.assertIn("Run Netbotpro with elevated privileges", " ".join(report["recommendations"]))

    def test_preflight_reports_not_ready_when_runtime_missing(self):
        provider = SystemCaptureProvider(
            interfaces_func=lambda: {"recommended": None, "recommended_label": None, "items": []},
            privilege_checker=_PrivilegeChecker(elevated=True),
            os_name_getter=lambda: "plan9",
            scapy_checker=lambda: (False, "missing"),
        )

        report = provider.preflight().to_dict()

        self.assertFalse(report["supported"])
        self.assertFalse(report["ready"])
        self.assertFalse(report["requires_elevation"])
        self.assertEqual(report["interface_count"], 0)
        self.assertEqual(report["checks"][0]["code"], "os_supported")
        self.assertFalse(report["checks"][1]["ok"])
        self.assertEqual(report["discovery_source"], "live")
        self.assertIn("No capture interfaces were detected", " ".join(report["recommendations"]))

    def test_list_interfaces_times_out_to_safe_empty_payload(self):
        provider = SystemCaptureProvider(
            interfaces_func=lambda: (__import__("time").sleep(0.2), {"recommended": "eth0", "recommended_label": "Ethernet", "items": [{"value": "eth0", "name": "Ethernet"}]})[1],
        )

        with patch("core.capture.system_provider.CAPTURE_CALL_TIMEOUT_SEC", 0.01):
            payload = provider.list_interfaces()

        self.assertEqual(payload["recommended"], None)
        self.assertEqual(payload["recommended_label"], None)
        self.assertEqual(payload["items"], [])

    def test_preflight_times_out_scapy_check_to_not_ready(self):
        provider = SystemCaptureProvider(
            interfaces_func=lambda: {"recommended": None, "recommended_label": None, "items": []},
            privilege_checker=_PrivilegeChecker(elevated=True),
            os_name_getter=lambda: "windows",
            scapy_checker=lambda: (__import__("time").sleep(0.2), (True, "ok"))[1],
        )

        with patch("core.capture.system_provider.CAPTURE_CALL_TIMEOUT_SEC", 0.01):
            report = provider.preflight().to_dict()

        self.assertFalse(report["ready"])
        self.assertFalse(report["checks"][1]["ok"])
        self.assertIn("timed out", report["checks"][1]["detail"].lower())

    def test_list_interfaces_uses_subprocess_payload_when_available(self):
        provider = SystemCaptureProvider()

        with patch.object(
            provider,
            "_run_interface_discovery_subprocess",
            return_value={
                "recommended": "eth0",
                "recommended_label": "Ethernet",
                "items": [{"value": "eth0", "name": "Ethernet", "label": "Ethernet", "recommended": True}],
            },
        ):
            payload = provider.list_interfaces()

        self.assertFalse(payload["degraded"])
        self.assertEqual(payload["source"], "live")
        self.assertEqual(payload["reason"], None)
        self.assertEqual(payload["recommended"], "eth0")
        self.assertEqual(len(payload["items"]), 1)

    def test_list_interfaces_subprocess_timeout_returns_cached_degraded_payload(self):
        provider = SystemCaptureProvider()

        with patch.object(
            provider,
            "_run_interface_discovery_subprocess",
            return_value={
                "recommended": "eth0",
                "recommended_label": "Ethernet",
                "items": [{"value": "eth0", "name": "Ethernet", "label": "Ethernet", "recommended": True}],
            },
        ):
            provider.list_interfaces()

        with patch.object(provider, "_run_interface_discovery_subprocess", side_effect=subprocess.TimeoutExpired(cmd="discover", timeout=0.1)):
            payload = provider.list_interfaces()

        self.assertTrue(payload["degraded"])
        self.assertEqual(payload["source"], "cache")
        self.assertEqual(payload["reason"], "interface_discovery_timeout")
        self.assertEqual(payload["recommended"], "eth0")
        self.assertEqual(len(payload["items"]), 1)

    def test_list_interfaces_subprocess_failure_returns_empty_fallback(self):
        provider = SystemCaptureProvider()

        with patch.object(provider, "_run_interface_discovery_subprocess", side_effect=RuntimeError("boom")):
            payload = provider.list_interfaces()

        self.assertTrue(payload["degraded"])
        self.assertEqual(payload["source"], "fallback")
        self.assertEqual(payload["reason"], "interface_discovery_failed")
        self.assertEqual(payload["items"], [])

    def test_preflight_includes_degraded_interface_recommendation(self):
        provider = SystemCaptureProvider(
            privilege_checker=_PrivilegeChecker(elevated=False),
            os_name_getter=lambda: "windows",
            scapy_checker=lambda: (False, "missing"),
        )

        with patch.object(provider, "_run_interface_discovery_subprocess", side_effect=RuntimeError("boom")):
            report = provider.preflight().to_dict()

        joined = " ".join(report["recommendations"])
        self.assertEqual(report["discovery_source"], "fallback")
        self.assertEqual(report["discovery_reason"], "interface_discovery_failed")
        self.assertIn("Npcap", joined)
        self.assertIn("Administrator", joined)


if __name__ == "__main__":
    unittest.main()
