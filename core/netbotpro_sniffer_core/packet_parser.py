from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .ip_utils import infer_flow, is_local_ip, is_public_ip, normalize_ip_set, parse_ip, preferred_remote_ip
from .layer7 import extract_layer7, extract_payload, safe_bytes_preview
from .providers import DefaultGeoIpProvider, DefaultMacVendorProvider, DefaultProcessMapper

logger = logging.getLogger(__name__)

LOCAL_COUNTRY_CODE = "IR"
TimestampFactory = Callable[[], str]


def captured_packet_length(pkt: Any) -> int:
    # libpcap supplies the original frame length; avoid Scapy reserialization.
    wire_length = getattr(pkt, "wirelen", None)
    if type(wire_length) is int and wire_length > 0:
        return wire_length
    return len(pkt)


@dataclass(frozen=True)
class PacketLayers:
    Ether: Any
    IP: Any
    TCP: Any
    UDP: Any
    ICMP: Any
    DNS: Any
    DNSQR: Any
    IPv6: Any = None
    ARP: Any = None
    ICMPv6: Any = None


@dataclass(slots=True)
class PacketMetadataBuilder:
    layers: PacketLayers
    enable_geoip: bool = True
    enable_mac_vendor: bool = True
    local_country_code: str = LOCAL_COUNTRY_CODE
    local_ips: set[str] | None = None
    geoip_provider: Any | None = None
    mac_vendor_provider: Any | None = None
    process_mapper: Any | None = None
    timestamp_factory: TimestampFactory | None = None
    capture_payload_preview: bool = True
    _capture_timestamp: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.geoip_provider is None:
            self.geoip_provider = DefaultGeoIpProvider(enabled=self.enable_geoip)
        if self.mac_vendor_provider is None:
            self.mac_vendor_provider = DefaultMacVendorProvider(enabled=self.enable_mac_vendor)
        if self.process_mapper is None:
            self.process_mapper = DefaultProcessMapper(enabled=True)
        if self.timestamp_factory is None:
            self._capture_timestamp = True
            self.timestamp_factory = lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        self.local_ips = normalize_ip_set(self.local_ips)

    def build(self, pkt: Any) -> dict[str, Any]:
        ts = self.timestamp_factory()
        if self._capture_timestamp:
            try:
                ts = datetime.fromtimestamp(float(pkt.time), timezone.utc).isoformat(timespec="milliseconds")
            except (AttributeError, TypeError, ValueError, OverflowError, OSError):
                pass
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
            "parent_pid": process.get("parent_pid"),
            "parent_process_name": process.get("parent_process_name"),
            "executable_path": process.get("executable_path"),
            "attribution_confidence": process.get("attribution_confidence"),
            "attribution_reason_unavailable": process.get("attribution_reason_unavailable"),
            "attribution_source": process.get("attribution_source"),
            "summary": summary,
        }
        meta.update({key: network[key] for key in ("seq", "ack", "window", "mss", "tcp_header_length", "payload_length") if key in network})
        meta.update(layer7)
        from core.protocol_intelligence import analyze_protocol
        classification = analyze_protocol(meta, include_metadata=False, payload_bytes=payload[:256])
        if classification["application_identified"]:
            meta.update(app_protocol=classification["app_protocol"], app_confidence=classification["confidence"],
                        protocol_basis=classification["detection_basis"])
        meta.update(safe_bytes_preview(payload, enabled=self.capture_payload_preview))
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
        length = captured_packet_length(pkt)
        tcp_fields: dict[str, Any] = {}

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
        elif self.layers.IPv6 is not None and self.layers.IPv6 in pkt:
            ip_layer = pkt[self.layers.IPv6]
            src, dst = ip_layer.src, ip_layer.dst
            ttl = int(ip_layer.hlim)
            proto = {6: "TCP", 17: "UDP", 58: "ICMPv6", 50: "ESP", 51: "AH"}.get(int(ip_layer.nh), str(ip_layer.nh))
        elif self.layers.ARP is not None and self.layers.ARP in pkt:
            arp = pkt[self.layers.ARP]
            src, dst, proto = arp.psrc, arp.pdst, "ARP"

        if self.layers.ICMPv6 is not None and self.layers.ICMPv6 in pkt:
            proto = "ICMPv6"

        if self.layers.TCP in pkt:
            tcp_layer = pkt[self.layers.TCP]
            sport = self._safe_port(getattr(tcp_layer, "sport", None))
            dport = self._safe_port(getattr(tcp_layer, "dport", None))
            flags = str(getattr(tcp_layer, "flags", ""))
            proto = "TCP"
            for key in ("seq", "ack", "window"):
                value = self._safe_port(getattr(tcp_layer, key, None))
                if value is not None:
                    tcp_fields[key] = value
            data_offset = self._safe_port(getattr(tcp_layer, "dataofs", None))
            if data_offset is not None:
                tcp_fields["tcp_header_length"] = data_offset * 4
            for option in getattr(tcp_layer, "options", None) or []:
                if isinstance(option, (tuple, list)) and len(option) == 2 and option[0] == "MSS":
                    value = self._safe_port(option[1])
                    if value is not None:
                        tcp_fields["mss"] = value
            tcp_payload = getattr(tcp_layer, "payload", None)
            if tcp_payload is not None:
                tcp_fields["payload_length"] = len(tcp_payload)
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
            **tcp_fields,
        }

    def _infer_direction(self, src: str | None, dst: str | None) -> dict[str, Any]:
        return infer_flow(src, dst, local_ips=self.local_ips)

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
        elif self._is_local_ip(src) and self._is_local_ip(dst):
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

    def _parse_ip(self, ip_addr: str | None) -> Any | None:
        return parse_ip(ip_addr)

    def _is_local_ip(self, ip_addr: str | None) -> bool:
        return is_local_ip(ip_addr, local_ips=self.local_ips)

    def _is_public_ip(self, ip_addr: str | None) -> bool:
        return is_public_ip(ip_addr, local_ips=self.local_ips)

    def _best_remote_ip(self, src: str | None, dst: str | None) -> str | None:
        return preferred_remote_ip(dst, src, local_ips=self.local_ips)

    def _plain_tcp_summary(self, pkt: Any) -> str | None:
        ether = pkt if type(pkt) is self.layers.Ether else None
        ip = ether.payload if ether is not None else pkt
        if (type(ip) is not self.layers.IP
                or self.layers.IP.__module__ != "scapy.layers.inet"):
            return None
        tcp = ip.payload
        if (type(tcp) is not self.layers.TCP
                or self.layers.TCP.__module__ != "scapy.layers.inet"):
            return None
        from scapy.config import conf
        from scapy.packet import NoPayload, Padding, Raw
        if (conf.emph.fields or conf.emph.layers
                or conf.resolve.fields or conf.resolve.layers
                or conf.noenum.fields or conf.noenum.layers or conf.raw_summary):
            return None
        # Only the standard payload-free summary grammar is rendered here.
        # Decoded applications, tunnels and custom formatting stay with Scapy.
        suffix = []
        tail = tcp.payload
        for _ in range(2):
            if type(tail) not in (Raw, Padding):
                break
            if tail.show_summary:
                suffix.append(type(tail).__name__)
            tail = tail.payload
        if type(tail) is not NoPayload:
            return None
        src = ip.get_field("src").i2repr(ip, ip.src)
        dst = ip.get_field("dst").i2repr(ip, ip.dst)
        sport = tcp.get_field("sport").i2repr(tcp, tcp.sport)
        dport = tcp.get_field("dport").i2repr(tcp, tcp.dport)
        flags = tcp.get_field("flags").i2repr(tcp, tcp.flags)
        prefix = ["Ether"] if ether is not None and ether.show_summary else []
        if ip.show_summary:
            prefix.append("IP")
        return " / ".join([*prefix, f"TCP {src}:{sport} > {dst}:{dport} {flags}", *suffix])

    def _safe_summary(self, pkt: Any) -> str:
        try:
            summary = self._plain_tcp_summary(pkt)
            if summary is not None:
                return summary
        except Exception:
            logger.debug("plain TCP summary unavailable", exc_info=True)
        try:
            return pkt.summary()
        except Exception:
            logger.debug("packet summary failed", exc_info=True)
            return ""
