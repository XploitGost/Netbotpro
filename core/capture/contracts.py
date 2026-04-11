from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol


PacketCallback = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class CaptureInterface:
    value: str
    name: str
    description: str = ""
    ip: str | None = None
    network_name: str | None = None
    label: str = ""
    is_up: bool = False
    recommended: bool = False

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "CaptureInterface":
        return cls(
            value=str(raw.get("value") or ""),
            name=str(raw.get("name") or ""),
            description=str(raw.get("description") or ""),
            ip=str(raw.get("ip") or "").strip() or None,
            network_name=str(raw.get("network_name") or "").strip() or None,
            label=str(raw.get("label") or raw.get("name") or ""),
            is_up=bool(raw.get("is_up")),
            recommended=bool(raw.get("recommended")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "name": self.name,
            "description": self.description,
            "ip": self.ip,
            "network_name": self.network_name,
            "label": self.label,
            "is_up": self.is_up,
            "recommended": self.recommended,
        }


@dataclass(frozen=True)
class CapturePreflightCheck:
    code: str
    label: str
    ok: bool
    severity: str = "error"
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "label": self.label,
            "ok": self.ok,
            "severity": self.severity,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class CapturePreflightReport:
    provider: str
    os_name: str
    supported: bool
    ready: bool
    requires_elevation: bool
    recommended_interface: str | None = None
    recommended_interface_label: str | None = None
    interface_count: int = 0
    checks: tuple[CapturePreflightCheck, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "os_name": self.os_name,
            "supported": self.supported,
            "ready": self.ready,
            "requires_elevation": self.requires_elevation,
            "recommended_interface": self.recommended_interface,
            "recommended_interface_label": self.recommended_interface_label,
            "interface_count": self.interface_count,
            "checks": [check.to_dict() for check in self.checks],
        }


class CaptureSession(Protocol):
    def start(self, iface: str | None = None) -> None:
        ...

    def stop(self) -> None:
        ...

    def selected_iface(self) -> str | None:
        ...


class InterfaceEnumerator(Protocol):
    def list_interfaces(self) -> dict[str, Any]:
        ...

    def describe_interface(self, candidate: str | None) -> str | None:
        ...

    def resolve_interface(self, candidate: str | None) -> str | None:
        ...


class PrivilegeChecker(Protocol):
    def is_elevated(self) -> bool:
        ...

    def detail(self, os_name: str) -> str:
        ...


class CaptureProvider(Protocol):
    name: str

    def create_session(self, packet_callback: PacketCallback) -> CaptureSession:
        ...

    def list_interfaces(self) -> dict[str, Any]:
        ...

    def describe_interface(self, candidate: str | None) -> str | None:
        ...

    def resolve_interface(self, candidate: str | None) -> str | None:
        ...

    def preflight(self) -> CapturePreflightReport:
        ...
