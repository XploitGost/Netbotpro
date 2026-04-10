from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from .layer7 import extract_layer7, extract_payload, safe_bytes_preview
from .providers import DefaultGeoIpProvider, DefaultMacVendorProvider, DefaultProcessMapper

logger = logging.getLogger(__name__)

LOCAL_COUNTRY_CODE = "IR"
TimestampFactory = Callable[[], str]


@dataclass(frozen=True)
class PacketLayers:
    Ether: Any
    IP: Any
    TCP: Any
    UDP: Any
    ICMP: Any
    DNS: Any
    DNSQR: Any


@dataclass(slots=True)
class PacketMetadataBuilder:
    layers: PacketLayers
    enable_geoip: bool = True
    enable_mac_vendor: bool = True
    local_country_code: str = LOCAL_COUNTRY_CODE
    geoip_provider: Any | None = None
    mac_vendor_provider: Any | None = None
    process_mapper: Any | None = None
    timestamp_factory: TimestampFactory | None = None

    def __post_init__(self) -> None:
        if self.geoip_provider is None:
            self.geoip_provider = DefaultGeoIpProvider(enabled=self.enable_geoip)
        if self.mac_vendor_provider is None:
            self.mac_vendor_provider = DefaultMacVendorProvider(enabled=self.enable_mac_vendor)
        if self.process_mapper is None:
            self.process_mapper = DefaultProcessMapper(enabled=True)
        if self.timestamp_factory is None:
            self.timestamp_factory = lambda: datetime.now().strftime("%H:%M:%S")

    def build(self, pkt: Any) -> dict[str, Any]:
        ts = self.timestamp_factory()
        src_mac, dst_mac = self._extract_macs(pkt)
        vendor_src = self._lookup_vendor(src_mac)
        vendor_dst = self._lookup_vendor(dst_mac)

        network = self._extract_network_fields(pkt)
        direction = self._infer_direction(network.get("src"), network.get("dst"))
        geo = self._lookup_geo(direction["remote_ip"])
        direction = self._finalize_scope(direction, geo, network.get("src"), network.get("dst"))
        process = self._resolve_process(direction, network)
        payload = extract_payload(pkt, self.layers)
        layer7 = extract_layer7(pkt, payload, self.layers)

        summary = self._safe_summary(pkt)
        meta: dict[str, Any] = {
            "ts": ts,
            "timestamp": ts,
            "src": network.get("src"),
            "dst": network.get("dst"),
            "proto": network.get("proto"),
            "sport": network.get("sport"),
            "dport": network.get("dport"),
            "flags": network.get("flags"),
            "length": network.get("length"),
            "ttl": network.get("ttl"),
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "vendor_src": vendor_src,
            "vendor_dst": vendor_dst,
            "direction": direction["direction"],
            "remote_ip": direction["remote_ip"],
            "scope": direction["scope"],
            "country": geo.get("country"),
            "country_code": geo.get("country"),
            "country_name": geo.get("country_name"),
            "city": geo.get("city"),
            "org": geo.get("org"),
            "isp": geo.get("isp"),
            "route": geo.get("route"),
            "asn": geo.get("asn"),
            "inside_outside": direction["inside_outside"],
            "pid": process.get("pid"),
            "process_name": process.get("process_name"),
            "summary": summary,
        }
        meta.update(layer7)
        meta.update(safe_bytes_preview(payload))
        return meta

    def _extract_macs(self, pkt: Any) -> tuple[str | None, str | None]:
        if self.layers.Ether not in pkt:
            return None, None
        ether = pkt[self.layers.Ether]
        return getattr(ether, "src", None), getattr(ether, "dst", None)

    def _lookup_vendor(self, mac_addr: str | None) -> str | None:
        if not mac_addr:
            return None
        try:
            return self.mac_vendor_provider.lookup(mac_addr)
        except Exception:
            logger.debug("vendor lookup failed for %s", mac_addr, exc_info=True)
            return None

    def _extract_network_fields(self, pkt: Any) -> dict[str, Any]:
        src = None
        dst = None
        ttl = None
        proto = "OTHER"
        sport = None
        dport = None
        flags = ""
        length = len(pkt)

        if self.layers.IP in pkt:
            ip_layer = pkt[self.layers.IP]
            src = getattr(ip_layer, "src", None)
            dst = getattr(ip_layer, "dst", None)
            try:
                ttl = int(getattr(ip_layer, "ttl", 0))
            except Exception:
                ttl = None
            try:
                proto_num = int(getattr(ip_layer, "proto", -1))
            except Exception:
                proto_num = -1
            proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, str(proto_num) if proto_num >= 0 else "OTHER")
        elif self.layers.ICMP in pkt:
            proto = "ICMP"

        if self.layers.TCP in pkt:
            tcp_layer = pkt[self.layers.TCP]
            sport = self._safe_port(getattr(tcp_layer, "sport", None))
            dport = self._safe_port(getattr(tcp_layer, "dport", None))
            flags = str(getattr(tcp_layer, "flags", ""))
            proto = "TCP"
        elif self.layers.UDP in pkt:
            udp_layer = pkt[self.layers.UDP]
            sport = self._safe_port(getattr(udp_layer, "sport", None))
            dport = self._safe_port(getattr(udp_layer, "dport", None))
            proto = "UDP"

        return {
            "src": src,
            "dst": dst,
            "ttl": ttl,
            "proto": proto,
            "sport": sport,
            "dport": dport,
            "flags": flags,
            "length": length,
        }

    def _infer_direction(self, src: str | None, dst: str | None) -> dict[str, Any]:
        is_src_private = self._is_private(src)
        is_dst_private = self._is_private(dst)
        direction = "OTHER"
        remote_ip = dst or src

        if is_src_private and not is_dst_private:
            direction = "OUTGOING"
            remote_ip = dst
        elif not is_src_private and is_dst_private:
            direction = "INCOMING"
            remote_ip = src
        elif is_src_private and is_dst_private:
            direction = "LOCAL"
            remote_ip = dst or src

        return {
            "direction": direction,
            "remote_ip": remote_ip,
        }

    def _finalize_scope(
        self,
        direction: dict[str, Any],
        geo: dict[str, Any],
        src: str | None,
        dst: str | None,
    ) -> dict[str, Any]:
        scope = "Unknown"
        country = geo.get("country")
        if country:
            scope = "Same-Country" if country == self.local_country_code else "International"
        elif self._is_private(src) and self._is_private(dst):
            scope = "Local/LAN"

        inside_outside = None
        if country:
            inside_outside = "INSIDE" if country == self.local_country_code else "OUTSIDE"

        return {
            **direction,
            "scope": scope,
            "inside_outside": inside_outside,
        }

    def _lookup_geo(self, ip_addr: str | None) -> dict[str, Any]:
        if not ip_addr or not self.enable_geoip:
            return {}
        try:
            return self.geoip_provider.lookup(ip_addr) or {}
        except Exception:
            logger.debug("geo lookup wrapper failed for %s", ip_addr, exc_info=True)
            return {}

    def _resolve_process(self, direction: dict[str, Any], network: dict[str, Any]) -> dict[str, Any]:
        local_ip = None
        local_port = None
        if direction["direction"] == "OUTGOING":
            local_ip = network.get("src")
            local_port = network.get("sport")
        elif direction["direction"] == "INCOMING":
            local_ip = network.get("dst")
            local_port = network.get("dport")

        if not local_ip or not local_port:
            return {}
        try:
            return self.process_mapper.resolve(local_ip, int(local_port), str(network.get("proto") or "")) or {}
        except Exception:
            logger.debug("process resolve wrapper failed", exc_info=True)
            return {}

    @staticmethod
    def _safe_port(value: Any) -> int | None:
        try:
            return int(value) if value is not None else None
        except Exception:
            return None

    @staticmethod
    def _is_private(ip_addr: str | None) -> bool:
        if not ip_addr:
            return False
        try:
            return ipaddress.ip_address(ip_addr).is_private
        except Exception:
            return False

    @staticmethod
    def _safe_summary(pkt: Any) -> str:
        try:
            return pkt.summary()
        except Exception:
            logger.debug("packet summary failed", exc_info=True)
            return ""
