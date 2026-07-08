from __future__ import annotations

import ctypes
import importlib
import json
import logging
import os
import platform
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any, Callable

from core.core_sniffer import NetSniffer
from core.netbotpro_sniffer_core import (
    describe_capture_interface,
    list_capture_interfaces,
    resolve_capture_interface,
)
from core.netbotpro_sniffer_core.interfaces import ensure_capture_backend

from .contracts import (
    CaptureInterface,
    CapturePreflightCheck,
    CapturePreflightReport,
    CaptureProvider,
    CaptureSession,
    PacketCallback,
    PrivilegeChecker,
)

logger = logging.getLogger(__name__)

SUPPORTED_CAPTURE_SYSTEMS = {"windows", "linux", "darwin"}
CAPTURE_CALL_TIMEOUT_SEC = float(os.environ.get("NETBOT_CAPTURE_CALL_TIMEOUT_SEC", "8.0"))
INTERFACE_DISCOVERY_TIMEOUT_SEC = float(os.environ.get("NETBOT_INTERFACE_DISCOVERY_TIMEOUT_SEC", "8.0"))
CAPTURE_BACKEND_PROBE_TIMEOUT_SEC = float(os.environ.get("NETBOT_CAPTURE_BACKEND_PROBE_TIMEOUT_SEC", "5.0"))
CAPTURE_BACKEND_PROBE_ARG = "--capture-backend-probe"
INTERFACE_DISCOVERY_ARG = "--capture-discovery-json"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
USE_SUBPROCESS_DISCOVERY = os.environ.get("NETBOT_USE_SUBPROCESS_INTERFACE_DISCOVERY", "").strip().lower() in {"1", "true", "yes"}


class DefaultPrivilegeChecker:
    def is_elevated(self) -> bool:
        system = platform.system().lower()
        if system == "windows":
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                logger.debug("windows privilege check failed", exc_info=True)
                return False
        geteuid = getattr(os, "geteuid", None)
        if geteuid is None:
            return False
        try:
            return geteuid() == 0
        except Exception:
            logger.debug("posix privilege check failed", exc_info=True)
            return False

    def detail(self, os_name: str) -> str:
        if os_name == "windows":
            return "Administrator privileges may be required for live capture and firewall actions."
        if os_name in {"linux", "darwin"}:
            return "Root privileges or capture capabilities may be required for live capture."
        return "Privilege requirements vary by platform."


class SystemCaptureProvider(CaptureProvider):
    name = "scapy-system"

    def __init__(
        self,
        session_factory: Callable[[PacketCallback], CaptureSession] | None = None,
        interfaces_func: Callable[[], dict[str, Any]] | None = None,
        describe_func: Callable[[str | None], str | None] | None = None,
        resolve_func: Callable[[str | None], str | None] | None = None,
        privilege_checker: PrivilegeChecker | None = None,
        os_name_getter: Callable[[], str] | None = None,
        scapy_checker: Callable[[], tuple[bool, str]] | None = None,
    ) -> None:
        self._using_default_session_factory = session_factory is None
        self._session_factory = session_factory or self._default_session_factory
        self._interfaces_func = interfaces_func or list_capture_interfaces
        self._describe_func = describe_func or describe_capture_interface
        self._resolve_func = resolve_func or resolve_capture_interface
        self._privilege_checker = privilege_checker or DefaultPrivilegeChecker()
        self._os_name_getter = os_name_getter or (lambda: platform.system().lower())
        self._scapy_checker = scapy_checker or self._default_scapy_checker
        self._last_interfaces_payload: dict[str, Any] | None = None
        self._last_interfaces_timeout_at = 0.0
        self._use_subprocess_interface_discovery = interfaces_func is None and USE_SUBPROCESS_DISCOVERY
        self._warm_capture_backend()

    def _warm_capture_backend(self) -> None:
        if os.environ.get("NETBOT_CAPTURE_WARM_BACKEND", "").strip().lower() not in {"1", "true", "yes"}:
            return
        if self._os_name_getter() != "windows":
            return
        if getattr(sys, "frozen", False):
            return
        if not self._using_default_session_factory:
            return
        try:
            ensure_capture_backend()
        except Exception:
            logger.debug("capture backend warmup failed", exc_info=True)

    @staticmethod
    def _capture_recommendations(
        *,
        os_name: str,
        supported: bool,
        scapy_ok: bool,
        interface_count: int,
        privileged: bool,
        interfaces: dict[str, Any],
    ) -> tuple[str, ...]:
        recommendations: list[str] = []
        if not supported:
            recommendations.append(f"Live capture is not supported on {os_name} in the current runtime.")
        if interfaces.get("degraded"):
            source = str(interfaces.get("source") or "fallback")
            reason = str(interfaces.get("reason") or "discovery_unavailable").replace("_", " ")
            recommendations.append(f"Interface discovery is degraded ({source}). Capture setup is relying on a fallback because {reason}.")
        if not scapy_ok:
            if os_name == "windows":
                recommendations.append("Check that Npcap and Scapy are installed correctly, then restart Netbotpro.")
            else:
                recommendations.append("Check the packet capture runtime dependencies for this host, then restart Netbotpro.")
        if interface_count <= 0:
            if os_name == "windows":
                recommendations.append("No capture adapters were detected. Verify Npcap is installed and at least one network adapter is enabled.")
            else:
                recommendations.append("No capture interfaces were detected. Verify that the host has an active network interface and capture access.")
        if not privileged:
            if os_name == "windows":
                recommendations.append("Run the desktop app as Administrator if you want live capture and firewall actions.")
            else:
                recommendations.append("Run Netbotpro with elevated privileges or capture capabilities if you need live capture.")
        recommended_label = str(interfaces.get("recommended_label") or "").strip()
        if recommended_label and interface_count > 0:
            recommendations.append(f"Recommended interface: {recommended_label}.")
        return tuple(recommendations[:4])

    @staticmethod
    def _call_with_timeout(callback: Callable[..., Any], *args: Any, fallback: Any, operation: str) -> Any:
        result: dict[str, Any] = {"value": fallback}
        error: dict[str, BaseException] = {}

        def runner() -> None:
            try:
                result["value"] = callback(*args)
            except BaseException as exc:  # pragma: no cover - defensive path
                error["exc"] = exc

        worker = threading.Thread(target=runner, name=f"netbotpro-{operation}", daemon=True)
        worker.start()
        worker.join(CAPTURE_CALL_TIMEOUT_SEC)
        if worker.is_alive():
            logger.warning("capture provider operation timed out: %s", operation)
            return fallback
        if "exc" in error:
            raise error["exc"]
        return result["value"]

    def create_session(self, packet_callback: PacketCallback) -> CaptureSession:
        return self._session_factory(packet_callback)

    def _default_session_factory(self, packet_callback: PacketCallback) -> CaptureSession:
        return NetSniffer(
            packet_callback,
            iface_resolver=self._recommended_interface_for_runtime,
            candidate_resolver=self.resolve_interface,
        )

    @staticmethod
    def _normalize_interfaces_payload(
        raw: dict[str, Any],
        *,
        degraded: bool,
        source: str,
        reason: str | None,
    ) -> dict[str, Any]:
        items = [CaptureInterface.from_raw(item).to_dict() for item in raw.get("items", [])]
        return {
            "recommended": raw.get("recommended"),
            "recommended_label": raw.get("recommended_label"),
            "items": items,
            "degraded": degraded,
            "source": source,
            "reason": reason,
        }

    def _fallback_interfaces_payload(self, reason: str) -> dict[str, Any]:
        cached = self._last_interfaces_payload
        if cached is not None:
            payload = dict(cached)
            payload["degraded"] = True
            payload["source"] = "cache"
            payload["reason"] = reason
            return payload
        return {
            "recommended": None,
            "recommended_label": None,
            "items": [],
            "degraded": True,
            "source": "fallback",
            "reason": reason,
        }

    def _interface_discovery_command(self) -> list[str]:
        if getattr(sys, "frozen", False):
            return [sys.executable, INTERFACE_DISCOVERY_ARG]
        return [sys.executable, "-m", "backend.app.desktop_entry", INTERFACE_DISCOVERY_ARG]

    def _capture_backend_probe_command(self) -> list[str]:
        if getattr(sys, "frozen", False):
            return [sys.executable, CAPTURE_BACKEND_PROBE_ARG]
        return [sys.executable, "-m", "backend.app.desktop_entry", CAPTURE_BACKEND_PROBE_ARG]

    def _run_interface_discovery_subprocess(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "timeout": INTERFACE_DISCOVERY_TIMEOUT_SEC,
            "check": False,
        }
        if not getattr(sys, "frozen", False):
            kwargs["cwd"] = str(PROJECT_ROOT)
        completed = subprocess.run(self._interface_discovery_command(), **kwargs)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or f"exit={completed.returncode}").strip()
            raise RuntimeError(f"interface discovery child failed: {detail}")
        try:
            return json.loads((completed.stdout or "").strip() or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("interface discovery child returned invalid JSON") from exc

    def _run_interface_discovery_inprocess(self) -> dict[str, Any] | None:
        fallback = self._last_interfaces_payload or {"recommended": None, "recommended_label": None, "items": []}
        raw = self._call_with_timeout(self._interfaces_func, fallback=fallback, operation="list-interfaces-inprocess")
        if raw is fallback:
            return None
        return raw

    def _known_interface_items(self) -> list[dict[str, Any]]:
        payload = self._last_interfaces_payload or self.list_interfaces()
        return list(payload.get("items", []))

    def _recommended_interface_for_runtime(self) -> str | None:
        payload = self.list_interfaces()
        recommended = str(payload.get("recommended") or "").strip()
        return recommended or None

    @staticmethod
    def _scapy_status_from_interfaces_payload(interfaces: dict[str, Any]) -> tuple[bool, str]:
        if interfaces.get("degraded"):
            reason = str(interfaces.get("reason") or "interface_discovery_unavailable").replace("_", " ")
            return False, f"Interface discovery is degraded: {reason}."
        return True, "Capture discovery child responded successfully."

    def list_interfaces(self) -> dict[str, Any]:
        try:
            if self._use_subprocess_interface_discovery:
                try:
                    raw = self._run_interface_discovery_subprocess()
                except subprocess.TimeoutExpired:
                    logger.warning("capture provider subprocess interface discovery timed out after %.2fs", INTERFACE_DISCOVERY_TIMEOUT_SEC)
                    raw = self._run_interface_discovery_inprocess()
                    if raw is None:
                        self._last_interfaces_timeout_at = time.monotonic()
                        return self._fallback_interfaces_payload("interface_discovery_timeout")
                except Exception:
                    logger.warning("capture provider subprocess interface discovery failed", exc_info=True)
                    raw = self._run_interface_discovery_inprocess()
                    if raw is None:
                        return self._fallback_interfaces_payload("interface_discovery_failed")
            else:
                fallback = self._last_interfaces_payload or {"recommended": None, "recommended_label": None, "items": []}
                raw = self._call_with_timeout(self._interfaces_func, fallback=fallback, operation="list-interfaces")
                if raw is fallback:
                    self._last_interfaces_timeout_at = time.monotonic()
                    return self._fallback_interfaces_payload("interface_discovery_timeout")
        except Exception:
            logger.warning("capture provider interface discovery failed", exc_info=True)
            return self._fallback_interfaces_payload("interface_discovery_failed")

        payload = self._normalize_interfaces_payload(raw, degraded=False, source="live", reason=None)
        self._last_interfaces_payload = payload
        return payload

    def describe_interface(self, candidate: str | None) -> str | None:
        resolved = self.resolve_interface(candidate) or str(candidate or "").strip() or None
        if not resolved:
            return None
        for item in self._known_interface_items():
            if item.get("value") == resolved:
                return str(item.get("name") or resolved)
        if self._use_subprocess_interface_discovery:
            return resolved
        return self._describe_func(candidate)

    def resolve_interface(self, candidate: str | None) -> str | None:
        text = str(candidate or "").strip()
        if not text or text in {"iface=default", "default"}:
            return None

        for item in self._known_interface_items():
            aliases = {
                item.get("value"),
                item.get("name"),
                item.get("network_name"),
                item.get("label"),
            }
            if text in {alias for alias in aliases if alias}:
                return str(item["value"])

        if self._use_subprocess_interface_discovery:
            return text
        return self._resolve_func(candidate)

    def preflight(self) -> CapturePreflightReport:
        os_name = str(self._os_name_getter() or "").strip().lower() or "unknown"
        supported = os_name in SUPPORTED_CAPTURE_SYSTEMS
        interfaces = self.list_interfaces()
        if self._use_subprocess_interface_discovery:
            scapy_ok, scapy_detail = self._scapy_status_from_interfaces_payload(interfaces)
        else:
            scapy_ok, scapy_detail = self._call_with_timeout(
                self._scapy_checker,
                fallback=(False, "Scapy runtime check timed out."),
                operation="scapy-check",
            )
        interface_count = len(interfaces.get("items", []))
        privileged = self._call_with_timeout(
            self._privilege_checker.is_elevated,
            fallback=False,
            operation="privilege-check",
        )

        checks = (
            CapturePreflightCheck(
                code="os_supported",
                label="OS Support",
                ok=supported,
                detail="Live capture provider is supported on this OS." if supported else f"Live capture provider is not supported on {os_name}.",
            ),
            CapturePreflightCheck(
                code="scapy_runtime",
                label="Scapy Runtime",
                ok=scapy_ok,
                detail=scapy_detail,
            ),
            CapturePreflightCheck(
                code="interfaces_available",
                label="Interfaces Available",
                ok=interface_count > 0,
                detail=f"Detected {interface_count} capture interface(s).",
            ),
            CapturePreflightCheck(
                code="privileges",
                label="Capture Privileges",
                ok=privileged,
                severity="warning",
                detail=self._privilege_checker.detail(os_name),
            ),
        )

        ready = supported and scapy_ok and interface_count > 0
        recommendations = self._capture_recommendations(
            os_name=os_name,
            supported=supported,
            scapy_ok=scapy_ok,
            interface_count=interface_count,
            privileged=privileged,
            interfaces=interfaces,
        )
        return CapturePreflightReport(
            provider=self.name,
            os_name=os_name,
            supported=supported,
            ready=ready,
            requires_elevation=not privileged,
            recommended_interface=str(interfaces.get("recommended") or "").strip() or None,
            recommended_interface_label=str(interfaces.get("recommended_label") or "").strip() or None,
            interface_count=interface_count,
            discovery_source=str(interfaces.get("source") or "").strip() or None,
            discovery_reason=str(interfaces.get("reason") or "").strip() or None,
            checks=checks,
            recommendations=recommendations,
        )

    def _default_scapy_checker(self) -> tuple[bool, str]:
        if self._os_name_getter() == "windows":
            try:
                completed = subprocess.run(
                    self._capture_backend_probe_command(),
                    capture_output=True,
                    text=True,
                    timeout=CAPTURE_BACKEND_PROBE_TIMEOUT_SEC,
                    check=False,
                    cwd=None if getattr(sys, "frozen", False) else str(PROJECT_ROOT),
                )
            except subprocess.TimeoutExpired:
                return (
                    False,
                    "Scapy/Npcap capture backend probe timed out. Restart Npcap and run Netbotpro as Administrator.",
                )
            except Exception as exc:
                return False, f"Scapy/Npcap capture backend probe failed: {exc.__class__.__name__}"
            if completed.returncode != 0:
                detail = (completed.stderr or completed.stdout or f"exit={completed.returncode}").strip()
                return False, f"Scapy/Npcap capture backend probe failed: {detail[:160]}"
            return True, "Scapy/Npcap capture backend probe passed."

        try:
            importlib.import_module("scapy.interfaces")
            importlib.import_module("scapy.sendrecv")
        except Exception as exc:
            return False, f"Scapy runtime is unavailable: {exc.__class__.__name__}"
        return True, "Scapy runtime is available."
