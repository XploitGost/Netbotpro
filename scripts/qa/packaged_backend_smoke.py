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
DESKTOP_PACKAGED_BACKEND_DIR = (
    PROJECT_ROOT
    / "desktop"
    / "electron"
    / "dist"
    / "win-unpacked"
    / "resources"
    / "runtime"
    / "backend"
)


def expected_binary_name(platform_name: str | None = None) -> str:
    platform_name = platform_name or os.sys.platform
    return (
        "netbotpro-backend.exe"
        if platform_name.startswith("win")
        else "netbotpro-backend"
    )


def resolve_runtime_dir(runtime_dir: Path = PACKAGED_BACKEND_DIR) -> Path:
    runtime_dir = Path(runtime_dir)
    if runtime_dir.exists():
        return runtime_dir
    if DESKTOP_PACKAGED_BACKEND_DIR.exists():
        return DESKTOP_PACKAGED_BACKEND_DIR
    return runtime_dir


def find_binary(runtime_dir: Path = PACKAGED_BACKEND_DIR) -> Path:
    runtime_dir = resolve_runtime_dir(runtime_dir)
    runtime_dir = Path(runtime_dir)
    binary_path = runtime_dir / expected_binary_name()
    if not binary_path.exists():
        raise FileNotFoundError(f"Packaged backend binary not found in {runtime_dir}")
    return binary_path


def list_support_files(runtime_dir: Path = PACKAGED_BACKEND_DIR) -> list[Path]:
    runtime_dir = resolve_runtime_dir(runtime_dir)
    runtime_dir = Path(runtime_dir)
    binary_path = find_binary(runtime_dir)
    return sorted(
        [entry for entry in runtime_dir.iterdir() if entry.name != binary_path.name],
        key=lambda item: item.name,
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _request_json(url: str, timeout_sec: float = 2.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout_sec) as response:
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


def validate_interfaces_payload(payload: dict) -> None:
    items = payload.get("items")
    if not isinstance(items, list):
        raise AssertionError("Interfaces payload must contain an items list")
    if payload.get("degraded"):
        if not payload.get("source"):
            raise AssertionError("Degraded interfaces payload must include a source")
        if not payload.get("reason"):
            raise AssertionError("Degraded interfaces payload must include a reason")
    recommendations = payload.get("recommendations")
    if recommendations is not None and not isinstance(recommendations, list):
        raise AssertionError("Interfaces recommendations must be a list when present")


def validate_monitoring_payload(payload: dict) -> None:
    attribution = payload.get("service_attribution")
    if not isinstance(attribution, dict):
        raise AssertionError("Monitoring payload must include service_attribution")
    if int(attribution.get("registry_size") or 0) < 1:
        raise AssertionError("Packaged service attribution registry is unavailable")
    if attribution.get("health") == "critical":
        raise AssertionError("Packaged service attribution health must not be critical")


def run_smoke(
    runtime_dir: Path = PACKAGED_BACKEND_DIR, timeout_sec: float = 20.0
) -> None:
    runtime_dir = resolve_runtime_dir(runtime_dir)
    runtime_dir = Path(runtime_dir)
    binary_path = find_binary(runtime_dir)
    support_files = list_support_files(runtime_dir)
    if not support_files:
        raise AssertionError(
            f"Expected staged support files next to {binary_path.name}"
        )

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
            status_payload = _wait_for_http(
                f"http://127.0.0.1:{port}/api/status", timeout_sec=timeout_sec
            )
            validate_status_payload(status_payload)
            interfaces_payload = _request_json(
                f"http://127.0.0.1:{port}/api/interfaces",
                timeout_sec=max(timeout_sec, 6.0),
            )
            validate_interfaces_payload(interfaces_payload)
            monitoring_payload = _request_json(
                f"http://127.0.0.1:{port}/api/monitoring/metrics",
                timeout_sec=max(timeout_sec, 6.0),
            )
            validate_monitoring_payload(monitoring_payload)
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
