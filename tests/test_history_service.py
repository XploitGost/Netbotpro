import unittest
from unittest.mock import patch
import asyncio

from backend.app.repositories.history_repository import HistoryRepositoryError
from backend.app.services.history_service import HistoryService


class _FakeRepository:
    def __init__(self, prefix: str, should_fail: bool = False) -> None:
        self.prefix = prefix
        self.should_fail = should_fail
        self.calls: list[tuple[str, object]] = []

    def _result(self, operation: str, payload: object):
        if self.should_fail:
            raise HistoryRepositoryError(f"{self.prefix} failed")
        self.calls.append((operation, payload))
        return {"source": self.prefix, "operation": operation}

    def list_packets(self, query):
        return self._result("list_packets", query)

    def list_alerts(self, query):
        return self._result("list_alerts", query)

    def get_packet_detail(self, packet_id):
        return self._result("get_packet_detail", packet_id)

    def get_alert_detail(self, alert_id):
        return self._result("get_alert_detail", alert_id)

    async def alist_packets(self, query):
        return self._result("alist_packets", query)

    async def alist_alerts(self, query):
        return self._result("alist_alerts", query)

    async def aget_packet_detail(self, packet_id):
        return self._result("aget_packet_detail", packet_id)

    async def aget_alert_detail(self, alert_id):
        return self._result("aget_alert_detail", alert_id)


class HistoryServiceTests(unittest.TestCase):
    @patch("backend.app.services.history_service.is_persist_enabled", return_value=False)
    def test_memory_mode_uses_memory_repository_only(self, _mock_persist):
        memory_repo = _FakeRepository("memory")
        sqlite_repo = _FakeRepository("sqlite")
        service = HistoryService(object(), sqlite_repository=sqlite_repo, memory_repository=memory_repo)

        result = service.get_packets({"src": "10.0.0.1"})

        self.assertEqual(result["source"], "memory")
        self.assertIn("query_ms", result)
        self.assertIn("observability", result)
        self.assertEqual(len(memory_repo.calls), 1)
        self.assertEqual(sqlite_repo.calls, [])

    @patch("backend.app.services.history_service.is_persist_enabled", return_value=True)
    def test_persist_mode_uses_sqlite_repository_only(self, _mock_persist):
        memory_repo = _FakeRepository("memory")
        sqlite_repo = _FakeRepository("sqlite")
        service = HistoryService(object(), sqlite_repository=sqlite_repo, memory_repository=memory_repo)

        result = service.get_alerts({"attack": "scan"})

        self.assertEqual(result["source"], "sqlite")
        self.assertEqual(len(sqlite_repo.calls), 1)
        self.assertEqual(memory_repo.calls, [])

    @patch("backend.app.services.history_service.is_persist_enabled", return_value=True)
    def test_async_persist_mode_uses_sqlite_repository_only(self, _mock_persist):
        memory_repo = _FakeRepository("memory")
        sqlite_repo = _FakeRepository("sqlite")
        service = HistoryService(object(), sqlite_repository=sqlite_repo, memory_repository=memory_repo)

        result = asyncio.run(service.aget_packets({"src": "8.8.8.8"}))

        self.assertEqual(result["source"], "sqlite")
        self.assertTrue(any(call[0] == "alist_packets" for call in sqlite_repo.calls))
        self.assertEqual(memory_repo.calls, [])

    @patch("backend.app.services.history_service.is_persist_enabled", return_value=True)
    def test_db_errors_propagate_without_memory_fallback(self, _mock_persist):
        memory_repo = _FakeRepository("memory")
        sqlite_repo = _FakeRepository("sqlite", should_fail=True)
        service = HistoryService(object(), sqlite_repository=sqlite_repo, memory_repository=memory_repo)

        with self.assertRaises(HistoryRepositoryError):
            service.get_packet_detail("1")

        self.assertEqual(memory_repo.calls, [])


if __name__ == "__main__":
    unittest.main()
