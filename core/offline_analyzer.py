from __future__ import annotations

import platform
import socket
import struct
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from backend.app.bootstrap import ensure_project_root_on_path

ensure_project_root_on_path()

from backend.app.services.sniffer_detection_pipeline import (
    SnifferDetectionPipeline,
)  # noqa: E402
from config.settings_manager import load_settings  # noqa: E402
from core.dns_intelligence import analyze_dns_packets  # noqa: E402
from core.flow_engine import FlowEngine  # noqa: E402
from core.http_intelligence import analyze_http_packets  # noqa: E402
from core.netbotpro_sniffer_core.packet_parser import (  # noqa: E402
    PacketLayers,
    PacketMetadataBuilder,
)
from core.packet_dissector import dissect_packet  # noqa: E402
from core.privacy_redaction import redact_sensitive_data  # noqa: E402
from core.tcp_analysis import analyze_tcp_packets  # noqa: E402
from core.tls_intelligence import analyze_tls_packets  # noqa: E402


class _OfflineProcessMapper:
    def resolve(self, local_ip: str, local_port: int, proto: str) -> dict[str, Any]:
        return {}


def _read_pcap(path: str):
    from scapy.utils import rdpcap  # type: ignore

    return rdpcap(path)


def _decode_dns_name(payload: bytes, offset: int = 12) -> str:
    labels: list[str] = []
    while offset < len(payload):
        size = payload[offset]
        offset += 1
        if size == 0:
            break
        if size & 0xC0 or offset + size > len(payload):
            return ""
        labels.append(payload[offset : offset + size].decode("ascii", errors="ignore"))
        offset += size
    return ".".join(part for part in labels if part)


def _pure_pcap_metadata(path: str) -> list[dict[str, Any]]:
    data = Path(path).read_bytes()
    if len(data) < 24:
        raise ValueError("PCAP file is truncated")
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError("Pure offline reader currently supports classic PCAP files")
    linktype = struct.unpack_from(f"{endian}I", data, 20)[0]
    if linktype != 1:
        raise ValueError("Pure offline reader requires Ethernet link type")

    rows: list[dict[str, Any]] = []
    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_frac, captured_len, _ = struct.unpack_from(
            f"{endian}IIII", data, offset
        )
        offset += 16
        frame = data[offset : offset + captured_len]
        offset += captured_len
        if len(frame) < 34 or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) < ihl or ihl < 20:
            continue
        proto_number = ip[9]
        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        transport = ip[ihl:]
        proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_number, "OTHER")
        sport = dport = None
        payload = b""
        if proto == "TCP" and len(transport) >= 20:
            sport, dport = struct.unpack_from("!HH", transport, 0)
            tcp_header_len = max(20, (transport[12] >> 4) * 4)
            payload = transport[tcp_header_len:]
        elif proto == "UDP" and len(transport) >= 8:
            sport, dport = struct.unpack_from("!HH", transport, 0)
            payload = transport[8:]
        row: dict[str, Any] = {
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "proto": proto,
            "transport": proto,
            "length": len(frame),
            "payload_len": len(payload),
            "summary": f"{proto} {src}:{sport or 0} -> {dst}:{dport or 0}",
            "ts": datetime.fromtimestamp(ts_sec + ts_frac / 1_000_000).strftime(
                "%H:%M:%S"
            ),
        }
        if proto == "UDP" and (sport == 53 or dport == 53) and len(payload) >= 12:
            row.update({"app_protocol": "DNS", "dns_qname": _decode_dns_name(payload)})
        if proto == "TCP" and payload:
            text = payload.decode("latin-1", errors="ignore")
            first_line = text.split("\r\n", 1)[0]
            parts = first_line.split(" ")
            if len(parts) >= 2 and parts[0] in {
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "HEAD",
                "OPTIONS",
                "PATCH",
            }:
                headers = {}
                for line in text.split("\r\n")[1:]:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        headers[key.strip().lower()] = value.strip()
                row.update(
                    {
                        "app_protocol": "HTTP",
                        "http_method": parts[0],
                        "http_path": parts[1],
                        "http_host": headers.get("host", ""),
                        "http_user_agent": headers.get("user-agent", ""),
                    }
                )
        rows.append(row)
    return rows


def _packet_timestamp(pkt: Any) -> str:
    try:
        return datetime.fromtimestamp(float(getattr(pkt, "time", 0.0))).strftime(
            "%H:%M:%S"
        )
    except Exception:
        return ""


def _packet_layers() -> PacketLayers:
    from scapy.config import conf  # type: ignore

    # Offline decoding does not need the native Npcap/libpcap socket backend.
    # Keeping it disabled prevents a broken Windows Npcap installation from
    # blocking PCAP file analysis while Scapy imports protocol layers.
    conf.use_pcap = False
    from scapy.layers.dns import DNS, DNSQR  # type: ignore
    from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore

    return PacketLayers(
        Ether=Ether,
        IP=IP,
        TCP=TCP,
        UDP=UDP,
        ICMP=ICMP,
        DNS=DNS,
        DNSQR=DNSQR,
    )


def _build_offline_pipeline(settings: dict[str, Any]) -> SnifferDetectionPipeline:
    return SnifferDetectionPipeline(settings_provider=lambda: dict(settings))


def _load_offline_settings() -> dict[str, Any]:
    # Keep offline PCAP analysis usable even when the FastAPI stack is absent.
    return load_settings()


def _build_meta(pkt: Any, builder: PacketMetadataBuilder, index: int) -> dict[str, Any]:
    meta = builder.build(pkt)
    ts = _packet_timestamp(pkt)
    meta["id"] = f"pcap-pkt-{index + 1}"
    meta["ts"] = ts
    meta["timestamp"] = ts
    return meta


def _top_pairs(
    counter: Counter, key_name: str, limit: int = 20
) -> list[dict[str, Any]]:
    return [
        {key_name: key, "count": count} for key, count in counter.most_common(limit)
    ]


def analyze_pcap_file(path: str, ml_threshold: float | None = None) -> dict[str, Any]:
    pure_metadata = (
        _pure_pcap_metadata(path)
        if platform.system() == "Windows" and Path(path).is_file()
        else None
    )
    layers = None if pure_metadata is not None else _packet_layers()
    packets = pure_metadata if pure_metadata is not None else _read_pcap(path)
    settings = _load_offline_settings()
    if ml_threshold is not None:
        settings["ids_ml_threshold"] = ml_threshold
    settings["auto_block"] = False

    builder = (
        PacketMetadataBuilder(layers=layers, process_mapper=_OfflineProcessMapper())
        if layers is not None
        else None
    )
    pipeline = _build_offline_pipeline(settings)

    alerts: list[dict[str, Any]] = []
    ip_counter: Counter = Counter()
    country_counter: Counter = Counter()
    port_counter: Counter = Counter()
    attack_counter: Counter = Counter()
    target_counter: Counter = Counter()
    protocol_counter: Counter = Counter()
    severity_counter: Counter = Counter()
    time_buckets: defaultdict[str, int] = defaultdict(int)
    flow_engine = FlowEngine()
    packet_details: list[dict[str, Any]] = []
    expert_items: list[dict[str, Any]] = []
    safe_packet_metadata: list[dict[str, Any]] = []

    for index, pkt in enumerate(packets):
        if isinstance(pkt, dict):
            meta = dict(pkt)
            meta["id"] = f"pcap-pkt-{index + 1}"
            meta["timestamp"] = meta.get("ts", "")
        else:
            meta = _build_meta(pkt, builder, index)

        src = meta.get("src")
        dst = meta.get("dst")
        remote_ip = meta.get("remote_ip")
        proto = meta.get("proto")

        if src:
            ip_counter[src] += 1
        if dst:
            ip_counter[dst] += 1
        if remote_ip:
            target_counter[remote_ip] += 1
        if meta.get("country"):
            country_counter[str(meta["country"])] += 1
        if meta.get("dport"):
            port_counter[int(meta["dport"])] += 1
        if proto:
            protocol_counter[str(proto)] += 1

        packet_alerts = pipeline.analyze(meta)
        if packet_alerts:
            minute_bucket = str(meta.get("ts") or "")[:5]
            if minute_bucket:
                time_buckets[minute_bucket] += len(packet_alerts)

        for alert in packet_alerts:
            row = dict(alert)
            row.setdefault("packet_id", meta.get("id"))
            alerts.append(row)
            if row.get("attack_type"):
                attack_counter[str(row["attack_type"])] += 1
            if row.get("severity"):
                severity_counter[str(row["severity"]).upper()] += 1
        flow_engine.ingest(meta, packet_alerts)
        safe_packet_metadata.append(redact_sensitive_data(meta))
        if len(packet_details) < 200:
            detail = dissect_packet(
                meta,
                capture_mode="metadata",
                related_alert_ids=[
                    str(item.get("id")) for item in packet_alerts if item.get("id")
                ],
            )
            packet_details.append(detail)
            expert_items.extend(detail["expert_items"])

    timeline = [
        {"time": key, "count": time_buckets[key]} for key in sorted(time_buckets)
    ]
    suspicious = bool(alerts)
    flow_summary = flow_engine.summary()
    conversations = flow_engine.conversations()

    return redact_sensitive_data(
        {
            "summary": {
                "total_packets": len(packets),
                "total_alerts": len(alerts),
                "attack_types": len(attack_counter),
                "status": "attacks_detected" if suspicious else "no_attacks_detected",
                "suspicious": suspicious,
            },
            "alerts": alerts,
            "top_ips": _top_pairs(ip_counter, "ip"),
            "top_countries": _top_pairs(country_counter, "country"),
            "top_ports": _top_pairs(port_counter, "port"),
            "top_attack_types": _top_pairs(attack_counter, "attack_type"),
            "top_targets": _top_pairs(target_counter, "target"),
            "top_protocols": _top_pairs(protocol_counter, "protocol"),
            "severity_breakdown": _top_pairs(severity_counter, "severity"),
            "timeline": timeline,
            "flows": flow_engine.list_flows(limit=500),
            "flow_summary": flow_summary,
            "top_conversations": conversations[:20],
            "top_risky_flows": flow_summary["top_risky_flows"],
            "protocol_summary": {
                "top_protocols": flow_summary["top_protocols"],
                "bytes_by_protocol": flow_summary["bytes_by_protocol"],
                "alerts_by_protocol": flow_summary["alerts_by_protocol"],
            },
            "protocol_intelligence": {
                "tcp": analyze_tcp_packets(safe_packet_metadata),
                "dns": analyze_dns_packets(safe_packet_metadata),
                "http": analyze_http_packets(safe_packet_metadata),
                "tls": analyze_tls_packets(safe_packet_metadata),
            },
            "risk_distribution": flow_summary["risk_distribution"],
            "conversation_timeline": [
                {
                    "conversation_id": item["conversation_id"],
                    "timeline": (
                        flow_engine.get_conversation(item["conversation_id"]) or {}
                    ).get("timeline", []),
                }
                for item in conversations[:20]
            ],
            "packet_details": packet_details,
            "expert_info": expert_items,
            "stream_summary": [
                {
                    "conversation_id": item["conversation_id"],
                    "protocols": item["protocols"],
                    "packets_count": item["packets_count"],
                    "bytes_total": item["bytes_total"],
                    "mode": "metadata",
                }
                for item in conversations[:20]
            ],
        }
    )
