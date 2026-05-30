from __future__ import annotations

import logging
import ipaddress
import platform
import socket
from typing import Any

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

logger = logging.getLogger(__name__)


def ensure_capture_backend() -> None:
    if platform.system().lower() != "windows":
        return
    try:
        from scapy.config import conf  # type: ignore

        if not getattr(conf, "use_pcap", False):
            conf.use_pcap = True
    except Exception:
        logger.debug("scapy pcap backend setup failed", exc_info=True)


def _detect_primary_local_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("1.1.1.1", 80))
            return sock.getsockname()[0]
    except Exception:
        logger.debug("primary local ip detection failed", exc_info=True)
        return None


def _is_loopback_name(name: str) -> bool:
    lowered = name.lower()
    return "loopback" in lowered or lowered.startswith("lo")


def _is_virtual_or_tunnel_name(name: str, description: str) -> bool:
    lowered = f"{name} {description}".lower()
    if name.strip().lower() == description.strip().lower() and len(name.strip()) <= 3:
        return True
    markers = (
        "bluetooth",
        "loopback",
        "miniport",
        "openvpn",
        "protonvpn",
        "tap-",
        "tap ",
        "teredo",
        "virtual",
        "vmnet",
        "vmware",
        "vpn",
        "wiresock",
    )
    return any(marker in lowered for marker in markers)


def _ip_quality(ip_addr: str | None) -> int:
    if not ip_addr:
        return 0
    try:
        parsed = ipaddress.ip_address(str(ip_addr).split("%", 1)[0])
    except ValueError:
        return 0
    if parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified:
        return 0
    if parsed.is_link_local:
        return 1
    if parsed.version == 4:
        return 3
    return 2


def _iface_value_from_obj(iface_obj: Any) -> str | None:
    network_name = getattr(iface_obj, "network_name", None)
    if network_name:
        return str(network_name)
    name = getattr(iface_obj, "name", None)
    if name:
        return str(name)
    return None


def _windows_pcap_value(guid: str | None) -> str | None:
    text = str(guid or "").strip()
    if not text:
        return None
    if text.startswith(r"\Device\NPF_"):
        return text
    return rf"\Device\NPF_{text}"


def _usable_windows_interface(raw: dict[str, Any]) -> bool:
    name = str(raw.get("name") or "")
    description = str(raw.get("description") or "")
    lowered = f"{name} {description}".lower()
    noisy_markers = (
        "-npcap packet driver",
        "-qos packet scheduler",
        "-wfp ",
        "-wiresock vpn client filter driver",
        "kernel debugger",
        "teredo",
        "6to4 adapter",
        "ip-https",
    )
    if any(marker in lowered for marker in noisy_markers):
        return False
    ips = [str(item).strip() for item in raw.get("ips", []) if str(item).strip()]
    return bool(ips) or "loopback" in lowered


def _windows_interfaces() -> list[dict[str, Any]]:
    if psutil is None:
        return []
    try:
        addrs_map = psutil.net_if_addrs()  # type: ignore[attr-defined]
    except Exception:
        logger.debug("psutil windows interface addresses unavailable", exc_info=True)
        return []
    try:
        stats_map = psutil.net_if_stats()  # type: ignore[attr-defined]
    except Exception:
        stats_map = {}

    items: list[dict[str, Any]] = []
    for name, addrs in addrs_map.items():
        name = str(name or "").strip()
        if not name:
            continue
        raw = {"name": name, "description": name, "ips": [getattr(addr, "address", "") for addr in addrs]}
        if not _usable_windows_interface(raw):
            continue
        value = name
        description = name
        ips = [str(item).split("%", 1)[0].strip() for item in raw.get("ips", []) if str(item).strip()]
        preferred_ip = next((ip for ip in ips if _ip_quality(ip) >= 3), None) or next((ip for ip in ips if _ip_quality(ip) > 0), None)
        iface_stats = stats_map.get(name)
        items.append(
            {
                "value": value,
                "name": name,
                "description": description,
                "ip": preferred_ip,
                "network_name": value,
                "label": _friendly_label(name, description, preferred_ip),
                "is_up": bool(getattr(iface_stats, "isup", False)) if iface_stats is not None else bool(preferred_ip),
            }
        )
    return items


def _friendly_label(name: str, description: str, ip_addr: str | None) -> str:
    parts = [name]
    if description and description != name:
        parts.append(description)
    if ip_addr:
        parts.append(ip_addr)
    return " - ".join(parts)


def _scapy_interfaces() -> list[dict[str, Any]]:
    ensure_capture_backend()
    if platform.system().lower() == "windows":
        return _windows_interfaces()
    try:
        from scapy.interfaces import IFACES  # type: ignore
    except Exception:
        logger.debug("scapy interface enumeration unavailable", exc_info=True)
        return []

    items: list[dict[str, Any]] = []
    for _, iface_obj in IFACES.items():
        value = _iface_value_from_obj(iface_obj)
        name = str(getattr(iface_obj, "name", "") or "").strip()
        if not value or not name:
            continue
        description = str(getattr(iface_obj, "description", "") or "").strip()
        ip_addr = str(getattr(iface_obj, "ip", "") or "").strip() or None
        items.append(
            {
                "value": value,
                "name": name,
                "description": description,
                "ip": ip_addr,
                "network_name": str(getattr(iface_obj, "network_name", "") or "").strip() or None,
                "label": _friendly_label(name, description, ip_addr),
            }
        )
    return items


def resolve_capture_interface(candidate: str | None) -> str | None:
    text = str(candidate or "").strip()
    if not text or text in {"iface=default", "default"}:
        return None

    for item in _scapy_interfaces():
        aliases = {
            item.get("value"),
            item.get("name"),
            item.get("network_name"),
            item.get("label"),
        }
        if text in {alias for alias in aliases if alias}:
            return str(item["value"])
    return None


def describe_capture_interface(candidate: str | None) -> str | None:
    resolved = resolve_capture_interface(candidate) or str(candidate or "").strip() or None
    if not resolved:
        return None
    for item in _scapy_interfaces():
        if item.get("value") == resolved:
            return str(item.get("name") or resolved)
    return resolved


def recommended_interface_name() -> str | None:
    items = _scapy_interfaces()
    if not items:
        return None

    target_ip = _detect_primary_local_ip()
    if target_ip:
        for item in items:
            iface_name = str(item.get("name") or "")
            description = str(item.get("description") or "")
            if item.get("ip") == target_ip and not _is_virtual_or_tunnel_name(iface_name, description):
                return str(item["value"])

    try:
        from scapy.config import conf  # type: ignore
        from scapy.interfaces import get_working_if  # type: ignore

        working = get_working_if()
        resolved = resolve_capture_interface(_iface_value_from_obj(working))
        if resolved:
            return resolved
        resolved = resolve_capture_interface(getattr(working, "name", None))
        if resolved:
            return resolved

        conf_iface = getattr(conf, "iface", None)
        resolved = resolve_capture_interface(_iface_value_from_obj(conf_iface))
        if resolved:
            return resolved
        resolved = resolve_capture_interface(getattr(conf_iface, "name", None))
        if resolved:
            return resolved
    except Exception:
        logger.debug("scapy interface recommendation failed", exc_info=True)

    stats: dict[str, Any] = {}
    if psutil is not None:
        try:
            stats = psutil.net_if_stats()  # type: ignore[attr-defined]
        except Exception:
            logger.debug("psutil fallback interface recommendation failed", exc_info=True)

    def score(item: dict[str, Any]) -> tuple[int, int, int, str]:
        iface_name = str(item.get("name") or "")
        description = str(item.get("description") or "")
        iface_stats = stats.get(iface_name)
        is_up = bool(getattr(iface_stats, "isup", False)) if iface_stats is not None else bool(item.get("ip"))
        physical_bonus = 0 if _is_virtual_or_tunnel_name(iface_name, description) else 1
        return (
            1 if is_up and not _is_loopback_name(iface_name) else 0,
            _ip_quality(str(item.get("ip") or "").strip() or None),
            physical_bonus,
            iface_name.lower(),
        )

    best = max(items, key=score)
    if score(best)[:3] != (0, 0, 0):
        return str(best["value"])
    return str(items[0]["value"])


def list_capture_interfaces() -> dict[str, Any]:
    items = _scapy_interfaces()
    recommended = recommended_interface_name()
    recommended_label = describe_capture_interface(recommended)

    stats_map: dict[str, Any] = {}
    if psutil is not None:
        try:
            stats_map = psutil.net_if_stats()  # type: ignore[attr-defined]
        except Exception:
            logger.debug("psutil interface stats unavailable", exc_info=True)

    for item in items:
        iface_name = str(item.get("name") or "")
        iface_stats = stats_map.get(iface_name)
        item["is_up"] = bool(getattr(iface_stats, "isup", False)) if iface_stats is not None else bool(item.get("ip"))
        item["recommended"] = item.get("value") == recommended

    items.sort(
        key=lambda item: (
            0 if item.get("recommended") else 1,
            0 if item.get("is_up") else 1,
            0 if item.get("ip") else 1,
            str(item.get("name") or "").lower(),
        )
    )
    return {
        "recommended": recommended,
        "recommended_label": recommended_label,
        "items": items,
    }


def interface_local_ips(candidate: str | None) -> set[str]:
    resolved = resolve_capture_interface(candidate) or str(candidate or "").strip() or None
    if not resolved:
        return set()

    ips: set[str] = set()
    interface_names: set[str] = set()

    for item in _scapy_interfaces():
        if item.get("value") != resolved:
            continue
        ip_addr = str(item.get("ip") or "").split("%", 1)[0].strip()
        if ip_addr:
            ips.add(ip_addr)
        for key in ("name", "network_name", "value"):
            text = str(item.get(key) or "").strip()
            if text:
                interface_names.add(text)

    if psutil is not None and interface_names:
        try:
            addrs_map = psutil.net_if_addrs()  # type: ignore[attr-defined]
            for iface_name in interface_names:
                for addr in addrs_map.get(iface_name, []):
                    family = getattr(addr, "family", None)
                    if family not in {socket.AF_INET, socket.AF_INET6}:
                        continue
                    text = str(getattr(addr, "address", "") or "").split("%", 1)[0].strip()
                    if text:
                        ips.add(text)
        except Exception:
            logger.debug("psutil interface address enumeration failed", exc_info=True)

    return ips
