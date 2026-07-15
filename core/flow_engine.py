from __future__ import annotations

import hashlib
import threading
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from core.conversation_model import conversation_id_for, timeline_event
from core.flow_risk import score_flow
from core.netbotpro_sniffer_core.ip_utils import is_local_ip
from core.privacy_redaction import redact_sensitive_text
from core.protocol_intelligence import analyze_protocol

_MAX_SAMPLE_PACKETS = 5
_MAX_TIMELINE_EVENTS = 200


def _timestamp(packet: dict[str, Any]) -> str:
    value = str(packet.get("ts") or packet.get("timestamp") or "").strip()
    return value or datetime.now(timezone.utc).isoformat()


def _epoch(value: str) -> float:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def direction_for(packet: dict[str, Any]) -> str:
    raw = str(packet.get("direction") or "").strip().upper()
    if raw == "OUTGOING":
        return "outbound"
    if raw == "INCOMING":
        return "inbound"
    src_local = is_local_ip(str(packet.get("src") or ""))
    dst_local = is_local_ip(str(packet.get("dst") or ""))
    if src_local and dst_local:
        return "internal"
    if src_local and not dst_local:
        return "outbound"
    if dst_local and not src_local:
        return "inbound"
    return "local"


def flow_key(packet: dict[str, Any]) -> tuple[str, str, int, int, str, str]:
    return (
        str(packet.get("src") or "-"),
        str(packet.get("dst") or "-"),
        int(packet.get("sport") or 0),
        int(packet.get("dport") or 0),
        str(packet.get("proto") or "OTHER").upper(),
        direction_for(packet),
    )


def flow_id_for(packet: dict[str, Any]) -> str:
    raw = "|".join(map(str, flow_key(packet)))
    return f"flow-{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def _safe_packet_sample(
    packet: dict[str, Any], protocol: dict[str, Any]
) -> dict[str, Any]:
    return {
        "id": packet.get("id"),
        "timestamp": _timestamp(packet),
        "src": packet.get("src"),
        "dst": packet.get("dst"),
        "sport": packet.get("sport"),
        "dport": packet.get("dport"),
        "transport": protocol["transport"],
        "app_protocol": protocol["app_protocol"],
        "length": int(packet.get("length") or 0),
        "summary": redact_sensitive_text(str(packet.get("summary") or "")),
        "metadata": deepcopy(protocol["metadata"]),
        "service_attribution": deepcopy(packet.get("service_attribution") or {}),
    }


class FlowEngine:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._flows: dict[str, dict[str, Any]] = {}
        self._conversations: dict[str, set[str]] = {}
        self._seen_destinations: set[str] = set()

    def ingest(
        self,
        packet: dict[str, Any],
        alerts: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        alerts = alerts or []
        protocol = analyze_protocol(packet)
        flow_id = flow_id_for(packet)
        conversation_id = conversation_id_for(packet)
        timestamp = _timestamp(packet)
        destination = str(packet.get("dst") or "")
        length = max(0, int(packet.get("length") or 0))
        direction = direction_for(packet)

        with self._lock:
            flow = self._flows.get(flow_id)
            created = flow is None
            if flow is None:
                flow = {
                    "flow_id": flow_id,
                    "conversation_id": conversation_id,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "duration_ms": 0,
                    "src_ip": packet.get("src"),
                    "dst_ip": packet.get("dst"),
                    "src_port": packet.get("sport"),
                    "dst_port": packet.get("dport"),
                    "transport": protocol["transport"],
                    "app_protocol": protocol["app_protocol"],
                    "protocol_confidence": protocol["confidence"],
                    "protocol_detection_basis": protocol["detection_basis"],
                    "protocol_unusual_port": bool(packet.get("protocol_unusual_port")),
                    "packets_count": 0,
                    "bytes_total": 0,
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "direction": direction,
                    "process_name": packet.get("process_name"),
                    "service_name": packet.get("service_name") or "Unknown",
                    "service_category": packet.get("service_category") or "Unknown",
                    "service_domain": packet.get("service_domain") or "",
                    "service_confidence": packet.get("service_confidence") or "unknown",
                    "service_reasons": list(packet.get("service_reasons") or []),
                    "service_sources": list(packet.get("service_sources") or []),
                    "service_confidence_score": int(
                        packet.get("service_confidence_score") or 0
                    ),
                    "service_attribution": deepcopy(
                        packet.get("service_attribution") or {}
                    ),
                    "country": packet.get("country_name") or packet.get("country"),
                    "asn": packet.get("asn"),
                    "related_alert_ids": [],
                    "alert_counts": Counter(),
                    "sample_packets": [],
                    "metadata": {},
                    "timeline": [],
                    "dns_failures": 0,
                    "new_destination": bool(
                        destination
                        and destination not in self._seen_destinations
                        and direction == "outbound"
                    ),
                }
                self._flows[flow_id] = flow
                self._conversations.setdefault(conversation_id, set()).add(flow_id)
                flow["timeline"].append(
                    timeline_event(
                        timestamp,
                        "flow_started",
                        f"{direction.title()} {protocol['transport']} flow started",
                        related_packet_id=str(packet.get("id") or "") or None,
                    )
                )

            flow["last_seen"] = timestamp
            flow["packets_count"] += 1
            flow["bytes_total"] += length
            if direction == "outbound":
                flow["bytes_sent"] += length
            elif direction == "inbound":
                flow["bytes_received"] += length
            else:
                flow["bytes_sent"] += length
            flow["metadata"].update(protocol["metadata"])
            if packet.get("service_name"):
                flow.update(
                    {
                        "service_name": packet.get("service_name"),
                        "service_category": packet.get("service_category"),
                        "service_domain": packet.get("service_domain"),
                        "service_confidence": packet.get("service_confidence"),
                        "service_reasons": list(packet.get("service_reasons") or []),
                        "service_sources": list(packet.get("service_sources") or []),
                        "service_confidence_score": int(
                            packet.get("service_confidence_score") or 0
                        ),
                        "service_attribution": deepcopy(
                            packet.get("service_attribution") or {}
                        ),
                    }
                )
            if len(flow["sample_packets"]) < _MAX_SAMPLE_PACKETS:
                flow["sample_packets"].append(_safe_packet_sample(packet, protocol))

            first_epoch, last_epoch = _epoch(flow["first_seen"]), _epoch(timestamp)
            flow["duration_ms"] = max(0, int((last_epoch - first_epoch) * 1000))
            if protocol["app_protocol"] != flow["app_protocol"] or created:
                flow["app_protocol"] = protocol["app_protocol"]
                flow["timeline"].append(
                    timeline_event(
                        timestamp,
                        "protocol_detected",
                        f"{protocol['app_protocol']} detected",
                        metadata={
                            "confidence": protocol["confidence"],
                            "basis": protocol["detection_basis"],
                        },
                        related_packet_id=str(packet.get("id") or "") or None,
                    )
                )

            event_type = {
                "DNS": "dns_query",
                "HTTP": "http_request",
                "TLS": "tls_handshake_metadata",
            }.get(protocol["app_protocol"])
            if event_type and protocol["metadata"]:
                if (
                    not flow["timeline"]
                    or flow["timeline"][-1].get("metadata") != protocol["metadata"]
                ):
                    flow["timeline"].append(
                        timeline_event(
                            timestamp,
                            event_type,
                            f"{protocol['app_protocol']} metadata observed",
                            metadata=deepcopy(protocol["metadata"]),
                            related_packet_id=str(packet.get("id") or "") or None,
                        )
                    )

            if (
                protocol["app_protocol"] == "DNS"
                and int(packet.get("dns_rcode") or 0) == 3
            ):
                flow["dns_failures"] += 1

            for alert in alerts:
                severity = str(alert.get("severity") or "low").lower()
                flow["alert_counts"][severity] += 1
                alert_id = str(alert.get("id") or "")
                if alert_id and alert_id not in flow["related_alert_ids"]:
                    flow["related_alert_ids"].append(alert_id)
                flow["timeline"].append(
                    timeline_event(
                        timestamp,
                        "alert_triggered",
                        redact_sensitive_text(
                            str(
                                alert.get("attack_type")
                                or alert.get("detail")
                                or "Alert"
                            )
                        ),
                        severity=severity,
                        related_packet_id=str(packet.get("id") or "") or None,
                        related_alert_id=alert_id or None,
                    )
                )

            if flow["new_destination"] and created:
                flow["timeline"].append(
                    timeline_event(
                        timestamp,
                        "unusual_destination",
                        "First observed outbound destination in this runtime",
                        severity="medium",
                        metadata={"destination": redact_sensitive_text(destination)},
                    )
                )
            if destination:
                self._seen_destinations.add(destination)
            flow["timeline"] = flow["timeline"][-_MAX_TIMELINE_EVENTS:]
            risk = score_flow(flow)
            flow["risk_score"] = risk["score"]
            flow["risk_level"] = risk["level"]
            flow["risk_reasons"] = risk["reasons"]
            return self._public_flow(flow)

    def reset(self) -> None:
        with self._lock:
            self._flows.clear()
            self._conversations.clear()
            self._seen_destinations.clear()

    def list_flows(self, **filters: Any) -> list[dict[str, Any]]:
        with self._lock:
            flows = [self._public_flow(flow) for flow in self._flows.values()]
        for field in ("protocol", "risk", "src_ip", "dst_ip", "direction"):
            value = str(filters.get(field) or "").strip().lower()
            if not value:
                continue
            target = (
                "app_protocol"
                if field == "protocol"
                else "risk_level" if field == "risk" else field
            )
            flows = [
                flow for flow in flows if value in str(flow.get(target) or "").lower()
            ]
        port = int(filters.get("port") or 0)
        if port:
            flows = [
                flow
                for flow in flows
                if port
                in {int(flow.get("src_port") or 0), int(flow.get("dst_port") or 0)}
            ]
        if filters.get("has_alerts"):
            flows = [flow for flow in flows if flow.get("related_alert_ids")]
        since = str(filters.get("since") or "").strip()
        if since:
            flows = [
                flow for flow in flows if str(flow.get("last_seen") or "") >= since
            ]
        sort = str(filters.get("sort") or "last_seen")
        sort_key = {
            "risk": "risk_score",
            "bytes": "bytes_total",
            "packets": "packets_count",
            "alerts": "related_alert_ids",
        }.get(sort, "last_seen")
        flows.sort(
            key=lambda item: (
                len(item.get(sort_key) or [])
                if sort_key == "related_alert_ids"
                else item.get(sort_key) or 0
            ),
            reverse=True,
        )
        return flows[: max(1, min(int(filters.get("limit") or 100), 500))]

    def get_flow(self, flow_id: str) -> dict[str, Any] | None:
        with self._lock:
            flow = self._flows.get(flow_id)
            return self._public_flow(flow) if flow else None

    def timeline(self, flow_id: str) -> list[dict[str, Any]]:
        flow = self.get_flow(flow_id)
        return list(flow.get("timeline") or []) if flow else []

    def conversations(self) -> list[dict[str, Any]]:
        with self._lock:
            items = []
            for conversation_id, flow_ids in self._conversations.items():
                flows = [self._public_flow(self._flows[item]) for item in flow_ids]
                items.append(
                    {
                        "conversation_id": conversation_id,
                        "flow_ids": sorted(flow_ids),
                        "flows_count": len(flows),
                        "packets_count": sum(item["packets_count"] for item in flows),
                        "bytes_total": sum(item["bytes_total"] for item in flows),
                        "risk_score": max(
                            (item["risk_score"] for item in flows), default=0
                        ),
                        "risk_level": max(
                            (item["risk_level"] for item in flows),
                            key=lambda value: {
                                "low": 0,
                                "medium": 1,
                                "high": 2,
                                "critical": 3,
                            }[value],
                            default="low",
                        ),
                        "protocols": sorted({item["app_protocol"] for item in flows}),
                        "first_seen": min(
                            (item["first_seen"] for item in flows), default=""
                        ),
                        "last_seen": max(
                            (item["last_seen"] for item in flows), default=""
                        ),
                    }
                )
        return sorted(items, key=lambda item: item["last_seen"], reverse=True)

    def get_conversation(self, conversation_id: str) -> dict[str, Any] | None:
        for item in self.conversations():
            if item["conversation_id"] == conversation_id:
                item["flows"] = [self.get_flow(flow_id) for flow_id in item["flow_ids"]]
                item["timeline"] = sorted(
                    [
                        event
                        for flow in item["flows"]
                        for event in flow.get("timeline", [])
                    ],
                    key=lambda event: event.get("timestamp") or "",
                )
                return item
        return None

    def summary(self) -> dict[str, Any]:
        flows = self.list_flows(limit=500)
        protocol_counts = Counter(item["app_protocol"] for item in flows)
        risk_counts = Counter(item["risk_level"] for item in flows)
        directions = Counter(item["direction"] for item in flows)
        bytes_by_protocol = Counter()
        alerts_by_protocol = Counter()
        destinations = Counter()
        ports = Counter()
        for item in flows:
            bytes_by_protocol[item["app_protocol"]] += item["bytes_total"]
            alerts_by_protocol[item["app_protocol"]] += len(item["related_alert_ids"])
            destinations[str(item.get("dst_ip") or "-")] += item["packets_count"]
            ports[int(item.get("dst_port") or 0)] += item["packets_count"]
        return {
            "total_flows": len(flows),
            "active_flows": len(flows),
            "external_flows": directions["outbound"] + directions["inbound"],
            "internal_flows": directions["internal"],
            "top_protocols": _counter_items(protocol_counts, "protocol"),
            "top_destinations": _counter_items(destinations, "destination"),
            "top_ports": _counter_items(ports, "port"),
            "top_risky_flows": sorted(
                flows, key=lambda item: item["risk_score"], reverse=True
            )[:10],
            "risk_distribution": dict(risk_counts),
            "bytes_by_protocol": dict(bytes_by_protocol),
            "alerts_by_protocol": dict(alerts_by_protocol),
        }

    @staticmethod
    def _public_flow(flow: dict[str, Any]) -> dict[str, Any]:
        public = deepcopy(flow)
        public["alert_counts"] = dict(public.get("alert_counts") or {})
        return public


def _counter_items(counter: Counter, key: str, limit: int = 10) -> list[dict[str, Any]]:
    return [{key: value, "count": count} for value, count in counter.most_common(limit)]


__all__ = ["FlowEngine", "direction_for", "flow_id_for", "flow_key"]
