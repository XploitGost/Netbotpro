from __future__ import annotations

import logging
import socket
from typing import Any

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

logger = logging.getLogger(__name__)


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


def _iface_value_from_obj(iface_obj: Any) -> str | None:
    network_name = getattr(iface_obj, "network_name", None)
    if network_name:
        return str(network_name)
    name = getattr(iface_obj, "name", None)
    if name:
        return str(name)
    return None


def _friendly_label(name: str, description: str, ip_addr: str | None) -> str:
    parts = [name]
    if description and description != name:
        parts.append(description)
    if ip_addr:
        parts.append(ip_addr)
    return " - ".join(parts)


def _scapy_interfaces() -> list[dict[str, Any]]:
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
            if item.get("ip") == target_ip:
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

    if psutil is not None:
        try:
            stats = psutil.net_if_stats()  # type: ignore[attr-defined]
            for item in items:
                iface_name = str(item.get("name") or "")
                iface_stats = stats.get(iface_name)
                if iface_stats and getattr(iface_stats, "isup", False) and not _is_loopback_name(iface_name):
                    return str(item["value"])
        except Exception:
            logger.debug("psutil fallback interface recommendation failed", exc_info=True)

    for item in items:
        iface_name = str(item.get("name") or "")
        if item.get("ip") and not _is_loopback_name(iface_name):
            return str(item["value"])
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
