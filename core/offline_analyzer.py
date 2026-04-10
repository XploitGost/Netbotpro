from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from scapy.all import DNS, DNSQR, Ether, ICMP, IP, TCP, UDP, rdpcap  # type: ignore

from backend.app.bootstrap import ensure_project_root_on_path

ensure_project_root_on_path()

from backend.app.services.settings_service import get_settings_snapshot  # noqa: E402
from backend.app.services.sniffer_detection_pipeline import SnifferDetectionPipeline  # noqa: E402
from core.netbotpro_sniffer_core.packet_parser import PacketLayers, PacketMetadataBuilder  # noqa: E402


class _OfflineProcessMapper:
    def resolve(self, local_ip: str, local_port: int, proto: str) -> dict[str, Any]:
        return {}


def _packet_timestamp(pkt: Any) -> str:
    try:
        return datetime.fromtimestamp(float(getattr(pkt, "time", 0.0))).strftime("%H:%M:%S")
    except Exception:
        return ""


def _packet_layers() -> PacketLayers:
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


def _build_meta(pkt: Any, builder: PacketMetadataBuilder, index: int) -> dict[str, Any]:
    meta = builder.build(pkt)
    ts = _packet_timestamp(pkt)
    meta["id"] = f"pcap-pkt-{index + 1}"
    meta["ts"] = ts
    meta["timestamp"] = ts
    return meta


def _top_pairs(counter: Counter, key_name: str, limit: int = 20) -> list[dict[str, Any]]:
    return [{key_name: key, "count": count} for key, count in counter.most_common(limit)]


def analyze_pcap_file(path: str, ml_threshold: float | None = None) -> dict[str, Any]:
    packets = rdpcap(path)
    settings = get_settings_snapshot()
    if ml_threshold is not None:
        settings["ids_ml_threshold"] = ml_threshold
    settings["auto_block"] = False

    builder = PacketMetadataBuilder(
        layers=_packet_layers(),
        process_mapper=_OfflineProcessMapper(),
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

    for index, pkt in enumerate(packets):
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

    timeline = [{"time": key, "count": time_buckets[key]} for key in sorted(time_buckets)]
    suspicious = bool(alerts)

    return {
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
    }
