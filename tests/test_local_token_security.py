import os
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from backend.app import main


class LocalTokenSecurityTests(unittest.TestCase):
    def _build_request(self, headers: dict[str, str] | None = None) -> Request:
        encoded_headers = [(key.lower().encode("latin-1"), value.encode("latin-1")) for key, value in (headers or {}).items()]
        scope = {"type": "http", "headers": encoded_headers, "client": ("127.0.0.1", 8765)}
        return Request(scope)

    @staticmethod
    def _route(path: str, method: str = "GET"):
        for route in main.app.routes:
            if getattr(route, "path", None) == path and method in getattr(route, "methods", set()):
                return route
        raise AssertionError(f"Route not found: {method} {path}")

    def test_status_reports_when_local_token_is_enabled(self):
        with (
            patch.dict(os.environ, {"NETBOT_LOCAL_TOKEN": "desktop-secret"}, clear=False),
            patch.object(main, "_observability_snapshot", return_value={}),
            patch.object(main.sniffer_service, "get_state", return_value={"running": False}),
        ):
            payload = main.api_status(None)

        self.assertTrue(payload["local_token_required"])

    def test_require_local_token_rejects_missing_header(self):
        with patch.dict(os.environ, {"NETBOT_LOCAL_TOKEN": "desktop-secret"}, clear=False):
            with self.assertRaises(HTTPException) as ctx:
                main.require_local_token(self._build_request())

        self.assertEqual(ctx.exception.status_code, 401)

    def test_require_local_token_accepts_expected_header(self):
        with patch.dict(os.environ, {"NETBOT_LOCAL_TOKEN": "desktop-secret"}, clear=False):
            result = main.require_local_token(self._build_request({"X-NetBot-Token": "desktop-secret"}))

        self.assertIsNone(result)

    def test_reports_route_declares_local_token_dependency(self):
        route = self._route("/api/reports")
        dependencies = {dependency.call for dependency in route.dependant.dependencies}
        self.assertIn(main.require_local_token, dependencies)

    def test_export_download_route_declares_local_token_dependency(self):
        route = self._route("/api/exports/download")
        dependencies = {dependency.call for dependency in route.dependant.dependencies}
        self.assertIn(main.require_local_token, dependencies)

    def test_investigation_export_route_declares_local_token_dependency(self):
        route = self._route("/api/exports/investigation", method="POST")
        dependencies = {dependency.call for dependency in route.dependant.dependencies}
        self.assertIn(main.require_local_token, dependencies)

    def test_raw_pcap_export_route_declares_local_token_dependency(self):
        route = self._route("/api/exports/raw-pcap")
        dependencies = {dependency.call for dependency in route.dependant.dependencies}
        self.assertIn(main.require_local_token, dependencies)

    def test_sniffer_start_keeps_trusted_client_and_token_dependencies(self):
        route = self._route("/api/sniffer/start", method="POST")
        dependencies = {dependency.call for dependency in route.dependant.dependencies}
        self.assertIn(main.require_trusted_client, dependencies)
        self.assertIn(main.require_local_token, dependencies)


if __name__ == "__main__":
    unittest.main()
