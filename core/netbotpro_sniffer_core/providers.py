from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class GeoIpProvider(Protocol):
    def lookup(self, ip_addr: str) -> dict[str, Any]:
        ...


class MacVendorProvider(Protocol):
    def lookup(self, mac_addr: str) -> str | None:
        ...


class ProcessMapper(Protocol):
    def resolve(self, local_ip: str, local_port: int, proto: str) -> dict[str, Any]:
        ...


@dataclass(slots=True)
class DefaultGeoIpProvider:
    enabled: bool = True

    def lookup(self, ip_addr: str) -> dict[str, Any]:
        if not self.enabled or not ip_addr:
            return {}
        try:
            from core.geoip_tools import geoip_lookup
        except Exception:
            logger.debug("geoip_tools import unavailable", exc_info=True)
            return {}
        try:
            return geoip_lookup(ip_addr) or {}
        except Exception:
            logger.debug("geoip lookup failed for %s", ip_addr, exc_info=True)
            return {}


@dataclass(slots=True)
class DefaultMacVendorProvider:
    enabled: bool = True

    def lookup(self, mac_addr: str) -> str | None:
        if not self.enabled or not mac_addr:
            return None
        try:
            from core.mac_vendor import lookup_vendor
        except Exception:
            logger.debug("mac_vendor import unavailable", exc_info=True)
            return None
        try:
            return lookup_vendor(mac_addr)
        except Exception:
            logger.debug("mac vendor lookup failed for %s", mac_addr, exc_info=True)
            return None


@dataclass(slots=True)
class DefaultProcessMapper:
    enabled: bool = True

    def resolve(self, local_ip: str, local_port: int, proto: str) -> dict[str, Any]:
        if not self.enabled or not local_ip or not local_port or proto not in {"TCP", "UDP"}:
            return {}
        try:
            from core.process_mapping import get_process_for_flow
        except Exception:
            logger.debug("process_mapping import unavailable", exc_info=True)
            return {}
        try:
            result = get_process_for_flow(local_ip, int(local_port), proto)
            return result if isinstance(result, dict) else {}
        except Exception:
            logger.debug(
                "process mapping failed for %s:%s/%s",
                local_ip,
                local_port,
                proto,
                exc_info=True,
            )
            return {}
