import socket
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from core import process_mapping


class _FakePsutilProcess:
    def __init__(self, pid: int) -> None:
        self._pid = pid

    def name(self) -> str:
        return "agent.exe" if self._pid == 4242 else "services.exe"

    def exe(self) -> str:
        return "C:/Program Files/Agent/agent.exe" if self._pid == 4242 else "C:/Windows/System32/services.exe"

    def ppid(self) -> int:
        return 4000 if self._pid == 4242 else 0


class _FakePsutil:
    def __init__(self, connections):
        self._connections = connections

    def net_connections(self, kind="inet"):
        return list(self._connections)

    def Process(self, pid):
        return _FakePsutilProcess(pid)


class ProcessMappingTests(unittest.TestCase):
    def setUp(self) -> None:
        process_mapping._CACHE.clear()
        process_mapping._PORT_CACHE.clear()
        process_mapping._WILDCARD_PORT_CACHE.clear()
        process_mapping._LAST_SCAN = 0.0

    def test_wildcard_bound_socket_maps_specific_local_ip(self):
        connection = SimpleNamespace(
            laddr=SimpleNamespace(ip="0.0.0.0", port=51820),
            type=socket.SOCK_DGRAM,
            pid=4242,
        )
        fake_psutil = _FakePsutil([connection])

        with patch.object(process_mapping, "psutil", fake_psutil):
            info = process_mapping.get_process_for_flow("192.168.1.50", 51820, "UDP")

        self.assertEqual(info["pid"], 4242)
        self.assertEqual(info["process_name"], "agent.exe")
        self.assertEqual(info["attribution_source"], "psutil")

    def test_lookup_refreshes_immediately_when_cache_misses(self):
        fake_info = {
            "pid": 4242,
            "process_name": "agent.exe",
            "parent_pid": 4000,
            "parent_process_name": "services.exe",
            "executable_path": "C:/Program Files/Agent/agent.exe",
            "attribution_confidence": "high",
            "attribution_reason_unavailable": None,
            "attribution_source": "psutil",
        }

        def fake_refresh():
            process_mapping._CACHE[("192.168.1.77", 443, "TCP")] = dict(fake_info)

        process_mapping._LAST_SCAN = 9999999999.0
        with patch.object(process_mapping, "_refresh_cache", side_effect=fake_refresh):
            info = process_mapping.get_process_for_flow("192.168.1.77", 443, "TCP")

        self.assertEqual(info["pid"], 4242)
        self.assertEqual(info["process_name"], "agent.exe")


if __name__ == "__main__":
    unittest.main()
