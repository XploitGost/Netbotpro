from __future__ import annotations

import importlib
import json
import os
import socket
import sys
import threading
import time
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

import uvicorn


REPO_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIST = REPO_ROOT / "frontend" / "dist" / "app.html"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _read_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=2) as response:
        return json.loads(response.read().decode("utf-8"))


def _wait_for_backend(base_url: str, timeout_sec: float = 60.0) -> dict:
    started = time.time()
    last_error: Exception | None = None
    while time.time() - started < timeout_sec:
        try:
            return _read_json(f"{base_url}/api/status")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            time.sleep(0.5)
    raise RuntimeError(f"backend smoke check failed: {last_error}")


def main() -> int:
    if not FRONTEND_DIST.exists():
        raise SystemExit(f"frontend bundle missing: {FRONTEND_DIST}")

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="netbotpro-desktop-smoke-") as td:
        env_updates = {
            "NETBOT_HOST": "127.0.0.1",
            "NETBOT_PORT": str(port),
            "NETBOT_CONFIG_DIR": str(Path(td) / "config"),
            "NETBOT_DATA_DIR": str(Path(td) / "data"),
            "NETBOT_LOG_DIR": str(Path(td) / "logs"),
            "NETBOT_ALLOWED_ORIGINS": "http://127.0.0.1:5173,http://localhost:5173,null,file://",
        }
        previous_env = {key: os.environ.get(key) for key in env_updates}
        for key, value in env_updates.items():
            os.environ[key] = value
        repo_root_str = str(REPO_ROOT)
        if repo_root_str not in sys.path:
            sys.path.insert(0, repo_root_str)

        backend_main = importlib.import_module("backend.app.main")
        backend_main = importlib.reload(backend_main)

        config = uvicorn.Config(backend_main.app, host="127.0.0.1", port=port, log_level="warning")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True, name="NetbotproDesktopSmoke")

        try:
            thread.start()
            status = _wait_for_backend(base_url)
            interfaces = _read_json(f"{base_url}/api/interfaces")
            if not status.get("ok"):
                raise RuntimeError("status endpoint did not report ok=true")
            if "capture_preflight" not in status:
                raise RuntimeError("status endpoint missing capture_preflight")
            if "preflight" not in interfaces:
                raise RuntimeError("interfaces endpoint missing preflight")
            preflight = interfaces["preflight"]
            if "provider" not in preflight or "checks" not in preflight:
                raise RuntimeError("capture preflight payload is incomplete")
            return 0
        finally:
            server.should_exit = True
            thread.join(timeout=15)
            for key, old_value in previous_env.items():
                if old_value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = old_value


if __name__ == "__main__":
    raise SystemExit(main())
