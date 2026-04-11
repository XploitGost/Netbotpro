from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGED_BACKEND_DIR = REPO_ROOT / "packaging" / "runtime" / "backend"


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
    raise RuntimeError(f"packaged backend smoke failed: {last_error}")


def find_binary() -> Path:
    candidates = [
        PACKAGED_BACKEND_DIR / "netbotpro-backend.exe",
        PACKAGED_BACKEND_DIR / "netbotpro-backend",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise SystemExit(f"packaged backend binary not found in {PACKAGED_BACKEND_DIR}")


def list_support_files(runtime_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in runtime_dir.iterdir()
        if path.name not in {"netbotpro-backend.exe", "netbotpro-backend"}
    )


def main() -> int:
    binary = find_binary()
    support_files = list_support_files(PACKAGED_BACKEND_DIR)
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    if not support_files:
        raise SystemExit(f"packaged backend runtime looks incomplete: {PACKAGED_BACKEND_DIR}")

    with tempfile.TemporaryDirectory(prefix="netbotpro-packaged-smoke-") as td:
        env = os.environ.copy()
        env.update(
            {
                "NETBOT_HOST": "127.0.0.1",
                "NETBOT_PORT": str(port),
                "NETBOT_CONFIG_DIR": str(Path(td) / "config"),
                "NETBOT_DATA_DIR": str(Path(td) / "data"),
                "NETBOT_LOG_DIR": str(Path(td) / "logs"),
                "NETBOT_ALLOWED_ORIGINS": "http://127.0.0.1:5173,http://localhost:5173,null,file://",
            }
        )
        process = subprocess.Popen(
            [str(binary)],
            cwd=str(binary.parent),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            status = _wait_for_backend(base_url)
            interfaces = _read_json(f"{base_url}/api/interfaces")
            if not status.get("ok"):
                raise RuntimeError("packaged backend status endpoint did not report ok=true")
            if "capture_preflight" not in status:
                raise RuntimeError("packaged backend status missing capture_preflight")
            if "project_root" in status:
                raise RuntimeError("packaged backend status unexpectedly exposed project_root")
            if "preflight" not in interfaces:
                raise RuntimeError("packaged backend interfaces payload missing preflight")
            preflight = interfaces["preflight"]
            if "provider" not in preflight or "checks" not in preflight:
                raise RuntimeError("packaged backend interfaces preflight is incomplete")
            return 0
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
