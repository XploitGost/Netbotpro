from __future__ import annotations

import ctypes
import importlib
import logging
import os
import platform
from typing import Any, Callable

from core.core_sniffer import NetSniffer
from core.netbotpro_sniffer_core import (
    describe_capture_interface,
    list_capture_interfaces,
    resolve_capture_interface,
)

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
        self._session_factory = session_factory or (lambda packet_callback: NetSniffer(packet_callback))
        self._interfaces_func = interfaces_func or list_capture_interfaces
        self._describe_func = describe_func or describe_capture_interface
        self._resolve_func = resolve_func or resolve_capture_interface
        self._privilege_checker = privilege_checker or DefaultPrivilegeChecker()
        self._os_name_getter = os_name_getter or (lambda: platform.system().lower())
        self._scapy_checker = scapy_checker or self._default_scapy_checker

    def create_session(self, packet_callback: PacketCallback) -> CaptureSession:
        return self._session_factory(packet_callback)

    def list_interfaces(self) -> dict[str, Any]:
        raw = self._interfaces_func()
        items = [CaptureInterface.from_raw(item).to_dict() for item in raw.get("items", [])]
        return {
            "recommended": raw.get("recommended"),
            "recommended_label": raw.get("recommended_label"),
            "items": items,
        }

    def describe_interface(self, candidate: str | None) -> str | None:
        return self._describe_func(candidate)

    def resolve_interface(self, candidate: str | None) -> str | None:
        return self._resolve_func(candidate)

    def preflight(self) -> CapturePreflightReport:
        os_name = str(self._os_name_getter() or "").strip().lower() or "unknown"
        supported = os_name in SUPPORTED_CAPTURE_SYSTEMS
        scapy_ok, scapy_detail = self._scapy_checker()
        interfaces = self.list_interfaces()
        interface_count = len(interfaces.get("items", []))
        privileged = self._privilege_checker.is_elevated()

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
        return CapturePreflightReport(
            provider=self.name,
            os_name=os_name,
            supported=supported,
            ready=ready,
            requires_elevation=not privileged,
            recommended_interface=str(interfaces.get("recommended") or "").strip() or None,
            recommended_interface_label=str(interfaces.get("recommended_label") or "").strip() or None,
            interface_count=interface_count,
            checks=checks,
        )

    @staticmethod
    def _default_scapy_checker() -> tuple[bool, str]:
        try:
            importlib.import_module("scapy.interfaces")
            importlib.import_module("scapy.sendrecv")
        except Exception as exc:
            return False, f"Scapy runtime is unavailable: {exc.__class__.__name__}"
        return True, "Scapy runtime is available."
