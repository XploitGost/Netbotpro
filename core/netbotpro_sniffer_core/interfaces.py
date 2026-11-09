from __future__ import annotations

import logging
import ipaddress
import platform
import socket
import threading
from typing import Any

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

logger = logging.getLogger(__name__)
_discovery_lock = threading.RLock()


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
    # Scapy reload replaces its global adapter registry. Do not enumerate it
    # concurrently from route discovery and metadata initialization.
    with _discovery_lock:
        return _enumerate_scapy_interfaces()


def _enumerate_scapy_interfaces() -> list[dict[str, Any]]:
    ensure_capture_backend()
    try:
        if platform.system().lower() == "windows":
            from scapy.all import conf
            conf.ifaces.reload()
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
    if platform.system().lower() == "windows":
        try:
            from scapy.arch.windows import get_windows_if_list
            wan = next((item for item in items if item["description"].lower() == "wan miniport (ip)"), None)
            wan6 = next((item for item in items if item["description"].lower() == "wan miniport (ipv6)"), None)
            if wan:
                for raw in get_windows_if_list():
                    if raw.get("type") != 23:
                        continue
                    ips = [str(ip).split("%", 1)[0] for ip in raw.get("ips", []) if _ip_quality(str(ip)) >= 2]
                    if not ips:
                        continue
                    name = str(raw["name"])
                    items.append({"value": "ras:" + name, "name": name,
                                  "description": "PPP VPN via WAN Miniport (IP)", "ip": ips[0],
                                  "network_name": "ras:" + name, "capture_device": wan["value"],
                                  "capture_ips": ips, "capture_device_ipv6": wan6["value"] if wan6 else None,
                                  "label": _friendly_label(name, "PPP VPN", ips[0])})
        except Exception:
            logger.debug("RAS interface enumeration failed", exc_info=True)
    return items


def capture_target(candidate: str | None) -> tuple[str | list[str] | None, str | None]:
    if str(candidate or "").startswith("ras:"):
        for item in _scapy_interfaces():
            if item["value"] == candidate and item.get("capture_device"):
                ips = [ipaddress.ip_address(ip) for ip in item["capture_ips"]]
                devices = [str(item["capture_device"])] if any(ip.version == 4 for ip in ips) else []
                if any(ip.version == 6 for ip in ips):
                    if not item.get("capture_device_ipv6"):
                        raise ValueError("PPP VPN has IPv6 addresses but Npcap WAN IPv6 capture is unavailable")
                    devices.append(str(item["capture_device_ipv6"]))
                target = devices[0] if len(devices) == 1 else devices
                return target, " or ".join("host " + str(ip) for ip in ips)
        raise ValueError("Selected PPP VPN is disconnected or its Npcap WAN capture device is unavailable")
    return candidate, None


def resolve_capture_interface(candidate: str | None, *, _items: list[dict[str, Any]] | None = None) -> str | None:
    text = str(candidate or "").strip()
    if not text or text in {"iface=default", "default"}:
        return None

    for item in (_scapy_interfaces() if _items is None else _items):
        aliases = {
            item.get("value"),
            item.get("name"),
            item.get("network_name"),
            item.get("label"),
        }
        if text in {alias for alias in aliases if alias}:
            return str(item["value"])
    return None


def describe_capture_interface(candidate: str | None, *, _items: list[dict[str, Any]] | None = None) -> str | None:
    if not str(candidate or '').strip():
        return None
    items = _scapy_interfaces() if _items is None else _items
    resolved = resolve_capture_interface(candidate, _items=items) or str(candidate or "").strip() or None
    if not resolved:
        return None
    for item in items:
        if item.get("value") == resolved:
            return str(item.get("name") or resolved)
    return resolved


def recommended_interface_name(*, _items: list[dict[str, Any]] | None = None) -> str | None:
    items = _scapy_interfaces() if _items is None else _items
    if not items:
        return None

    system_name = platform.system().lower()
    target_ip = _detect_primary_local_ip()
    if target_ip:
        for item in items:
            iface_name = str(item.get("name") or "")
            description = str(item.get("description") or "")
            if item.get("ip") == target_ip:
                return str(item["value"])

    if system_name != "windows":
        try:
            from scapy.config import conf  # type: ignore
            from scapy.interfaces import get_working_if  # type: ignore

            working = get_working_if()
            resolved = resolve_capture_interface(_iface_value_from_obj(working), _items=items)
            if resolved:
                return resolved
            resolved = resolve_capture_interface(getattr(working, "name", None), _items=items)
            if resolved:
                return resolved

            conf_iface = getattr(conf, "iface", None)
            resolved = resolve_capture_interface(_iface_value_from_obj(conf_iface), _items=items)
            if resolved:
                return resolved
            resolved = resolve_capture_interface(getattr(conf_iface, "name", None), _items=items)
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
            physical_bonus,
            1 if is_up and not _is_loopback_name(iface_name) else 0,
            _ip_quality(str(item.get("ip") or "").strip() or None),
            iface_name.lower(),
        )

    best = max(items, key=score)
    if score(best)[:3] != (0, 0, 0):
        return str(best["value"])
    return str(items[0]["value"])


def _active_openvpn_provider() -> str | None:
    if psutil is None or platform.system().lower() != "windows":
        return None
    try:
        parents = set()
        for process in psutil.process_iter(["name"]):
            if str(process.info.get("name") or "").lower() == "openvpn.exe":
                try:
                    parents.add(process.ppid())
                except (psutil.Error, OSError):
                    continue
        if not parents:
            return None
        providers = set()
        for service in psutil.win_service_iter():
            try:
                if service.pid() not in parents:
                    continue
                path = service.binpath().lower().replace("/", "\\")
                for vendor in ("Ivacy", "Surfshark", "NordVPN", "ProtonVPN", "ExpressVPN"):
                    if "\\" + vendor.lower() + "\\" in path:
                        providers.add(vendor)
            except (psutil.Error, OSError):
                continue
        return next(iter(providers)) if len(providers) == 1 else None
    except Exception:
        logger.debug("VPN engine ownership unavailable", exc_info=True)
        return None


def _label_active_connection(items: list[dict[str, Any]], recommended: str | None,
                             provider: str | None) -> None:
    # A client process alone cannot brand an adapter: require one active tunnel
    # on the selected route, plus a running engine owned by the vendor service.
    tunnels = [item for item in items if item.get("is_up") and
               "tap-windows" in str(item.get("description") or "").lower()]
    if provider and len(tunnels) == 1 and tunnels[0].get("value") == recommended:
        tunnels[0]["connection_name"] = provider
        tunnels[0]["connection_name_source"] = "active_engine_service_and_unique_routed_tap"


def list_capture_interfaces() -> dict[str, Any]:
    items = _scapy_interfaces()
    recommended = recommended_interface_name(_items=items)
    recommended_label = describe_capture_interface(recommended, _items=items)

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

    _label_active_connection(items, recommended, _active_openvpn_provider())

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
    if str(candidate or '').strip() in ('', 'default', 'iface=default'):
        return set()
    items = _scapy_interfaces()
    resolved = resolve_capture_interface(candidate, _items=items) or str(candidate or "").strip() or None
    if not resolved:
        return set()

    ips: set[str] = set()
    interface_names: set[str] = set()

    for item in items:
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
