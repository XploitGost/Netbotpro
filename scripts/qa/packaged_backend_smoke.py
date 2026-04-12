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


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGED_BACKEND_DIR = PROJECT_ROOT / "packaging" / "runtime" / "backend"


def expected_binary_name(platform_name: str | None = None) -> str:
    platform_name = platform_name or os.sys.platform
    return "netbotpro-backend.exe" if platform_name.startswith("win") else "netbotpro-backend"


def find_binary(runtime_dir: Path = PACKAGED_BACKEND_DIR) -> Path:
    runtime_dir = Path(runtime_dir)
    binary_path = runtime_dir / expected_binary_name()
    if not binary_path.exists():
        raise FileNotFoundError(f"Packaged backend binary not found in {runtime_dir}")
    return binary_path


def list_support_files(runtime_dir: Path = PACKAGED_BACKEND_DIR) -> list[Path]:
    runtime_dir = Path(runtime_dir)
    binary_path = find_binary(runtime_dir)
    return sorted([entry for entry in runtime_dir.iterdir() if entry.name != binary_path.name], key=lambda item: item.name)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _request_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=2) as response:
        return json.loads(response.read().decode("utf-8"))


def _wait_for_http(url: str, timeout_sec: float = 20.0) -> dict:
    started = time.time()
    while time.time() - started < timeout_sec:
        try:
            return _request_json(url)
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            time.sleep(0.5)
    raise TimeoutError(f"Timed out waiting for {url}")


def validate_status_payload(payload: dict) -> None:
    if "project_root" in payload:
        raise AssertionError("Status payload must not expose project_root")


def run_smoke(runtime_dir: Path = PACKAGED_BACKEND_DIR, timeout_sec: float = 20.0) -> None:
    runtime_dir = Path(runtime_dir)
    binary_path = find_binary(runtime_dir)
    support_files = list_support_files(runtime_dir)
    if not support_files:
        raise AssertionError(f"Expected staged support files next to {binary_path.name}")

    port = _free_port()
    with tempfile.TemporaryDirectory() as td:
        temp_root = Path(td)
        env = {
            **os.environ,
            "NETBOT_HOST": "127.0.0.1",
            "NETBOT_PORT": str(port),
            "NETBOT_CONFIG_DIR": str(temp_root / "config"),
            "NETBOT_DATA_DIR": str(temp_root / "data"),
            "NETBOT_LOG_DIR": str(temp_root / "logs"),
        }
        process = subprocess.Popen(
            [str(binary_path)],
            cwd=str(runtime_dir),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            status_payload = _wait_for_http(f"http://127.0.0.1:{port}/api/status", timeout_sec=timeout_sec)
            validate_status_payload(status_payload)
            _request_json(f"http://127.0.0.1:{port}/api/interfaces")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main() -> int:
    run_smoke()
    print("Packaged backend smoke passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
