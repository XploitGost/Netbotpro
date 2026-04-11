import unittest

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
        self.assertEqual(report["checks"][2]["code"], "interfaces_available")

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


if __name__ == "__main__":
    unittest.main()
