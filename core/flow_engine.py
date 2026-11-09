from __future__ import annotations

import hashlib
import threading
import time
from collections import Counter, OrderedDict
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from typing import Any

from core.conversation_model import conversation_id_for, timeline_event
from core.flow_compaction import DETAIL_FIELDS, PACKED_FIELD, ALERT_COUNT_FIELD, RAW_BYTES_FIELD, pack_flow, expand_flow, alert_count
from core.flow_risk import score_flow
from core.netbotpro_sniffer_core.ip_utils import is_local_ip
from core.privacy_redaction import redact_sensitive_data, redact_sensitive_text
from core.protocol_intelligence import analyze_protocol

_MAX_SAMPLE_PACKETS = 5
_MAX_TIMELINE_EVENTS = 200


def _detach_summary_value(value: Any) -> Any:
    if value is None or type(value) in (str, int, float, bool):
        return value
    scalar = (str, int, float, bool, type(None))
    if type(value) is list and all(type(item) in scalar for item in value):
        return value.copy()
    if type(value) in (dict, Counter) and all(
        type(key) in scalar and type(item) in scalar for key, item in value.items()
    ):
        return value.copy()
    return deepcopy(value)


def _timestamp(packet: dict[str, Any]) -> str:
    value = str(packet.get("ts") or packet.get("timestamp") or "").strip()
    return value or datetime.now(timezone.utc).isoformat()


def _epoch(value: str) -> float:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        try:
            clock = datetime.strptime(value, "%H:%M:%S").time()
            return datetime.combine(datetime.now().date(), clock).timestamp()
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
        "destination_domain": packet.get("destination_domain") or "",
        "destination_domain_source": packet.get("destination_domain_source") or "",
    }


class FlowEngine:
    def __init__(self, *, clock=None) -> None:
        self._lock = threading.RLock()
        self._flows: dict[str, dict[str, Any]] = {}
        self._alert_ids: dict[str, set[str]] = {}
        self._conversations: dict[str, set[str]] = {}
        self._seen_destinations: set[str] = set()
        self._monitor_directions: Counter[str] = Counter()
        self._monitor_risks: Counter[str] = Counter()
        self._clock = clock or time.monotonic
        self._hot_flows = OrderedDict()
        self._cold_count = self._cold_bytes = 0
        self._cold_json_bytes = 0
        self._compacted_total = self._restored_total = self._unpackable_total = 0

    def ingest(
        self,
        packet: dict[str, Any],
        alerts: list[dict[str, Any]] | None = None,
        *,
        redact_snapshot: bool = False,
        compact_snapshot: bool = False,
        live_summary: bool = False,
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
            if flow is not None and PACKED_FIELD in flow:
                restored = expand_flow(flow)
                self._cold_bytes -= len(flow[PACKED_FIELD])
                self._cold_json_bytes -= flow[RAW_BYTES_FIELD]
                self._cold_count -= 1
                flow = restored
                self._flows[flow_id] = flow
                if flow.get('related_alert_ids'):
                    self._alert_ids[flow_id] = set(flow['related_alert_ids'])
                self._restored_total += 1
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
                    "destination_domain": packet.get("destination_domain") or "",
                    "destination_domain_source": packet.get("destination_domain_source") or "",
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
                self._monitor_directions[direction] += 1
                self._conversations.setdefault(conversation_id, set()).add(flow_id)
                flow["timeline"].append(
                    timeline_event(
                        timestamp,
                        "flow_started",
                        f"{direction.title()} {protocol['transport']} flow started",
                        related_packet_id=str(packet.get("id") or "") or None,
                    )
                )

            self._hot_flows[flow_id] = self._clock()
            self._hot_flows.move_to_end(flow_id)
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
            if packet.get("destination_domain"):
                current_source = flow.get("destination_domain_source") or ""
                source = packet.get("destination_domain_source") or ""
                if source != "DNS answer (correlated)" or not current_source:
                    flow["destination_domain"] = packet["destination_domain"]
                    flow["destination_domain_source"] = source
            if packet.get("service_name"):
                flow.update(
                    {
                        "service_name": packet.get("service_name"),
                        "service_category": packet.get("service_category"),
                        "service_domain": packet.get("service_domain") or flow.get("service_domain"),
                        "service_confidence": packet.get("service_confidence"),
                        "service_reasons": list(packet.get("service_reasons") or []),
                        "service_sources": list(packet.get("service_sources") or []),
                        "service_confidence_score": int(
                            packet.get("service_confidence_score") or 0
                        ),
                    }
                )
                attribution = packet.get("service_attribution") or {}
                if attribution != flow.get("service_attribution"):
                    flow["service_attribution"] = deepcopy(attribution)
            if len(flow["sample_packets"]) < _MAX_SAMPLE_PACKETS:
                flow["sample_packets"].append(_safe_packet_sample(packet, protocol))

            first_epoch, last_epoch = _epoch(flow["first_seen"]), _epoch(timestamp)
            if last_epoch < first_epoch and "T" not in timestamp and "T" not in flow["first_seen"]:
                last_epoch += timedelta(days=1).total_seconds()
            flow["duration_ms"] = max(0, int((last_epoch - first_epoch) * 1000))
            confidence_rank = {"low": 0, "medium": 1, "high": 2}
            retain_previous = not created and flow["app_protocol"] != "UNKNOWN" and (
                protocol["app_protocol"] == "UNKNOWN" or
                confidence_rank.get(protocol["confidence"], 0) < confidence_rank.get(flow["protocol_confidence"], 0)
            )
            if retain_previous:
                protocol = {**protocol, "app_protocol": flow["app_protocol"],
                            "confidence": flow["protocol_confidence"], "detection_basis": flow["protocol_detection_basis"]}
            flow["display_protocol"] = protocol["app_protocol"] if protocol["app_protocol"] != "UNKNOWN" else flow["transport"]
            flow["application_identified"] = protocol["app_protocol"] != "UNKNOWN"
            if protocol["app_protocol"] == flow["app_protocol"] and not retain_previous:
                flow["protocol_confidence"] = protocol["confidence"]
                flow["protocol_detection_basis"] = protocol["detection_basis"]
            if protocol["app_protocol"] != flow["app_protocol"] or created:
                flow["app_protocol"] = protocol["app_protocol"]
                flow["protocol_confidence"] = protocol["confidence"]
                flow["protocol_detection_basis"] = protocol["detection_basis"]
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
                known_alerts = self._alert_ids.setdefault(flow["flow_id"], set())
                if alert_id and alert_id not in known_alerts:
                    flow["related_alert_ids"].append(alert_id)
                    known_alerts.add(alert_id)
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
            previous_risk = flow.get("risk_level")
            if previous_risk != risk["level"]:
                if previous_risk is not None:
                    self._monitor_risks[previous_risk] -= 1
                    if not self._monitor_risks[previous_risk]:
                        del self._monitor_risks[previous_risk]
                self._monitor_risks[risk["level"]] += 1
            flow["risk_score"] = risk["score"]
            flow["risk_level"] = risk["level"]
            flow["risk_reasons"] = risk["reasons"]
            snapshot = flow
            if live_summary:
                deferred = {'timeline', 'related_alert_ids', 'sample_packets', 'metadata', 'service_attribution'}
                snapshot = {key: value for key, value in flow.items() if key not in deferred}
                snapshot['details_deferred'] = True
                for field in ('timeline', 'related_alert_ids', 'sample_packets'):
                    snapshot[field] = []
                    snapshot[f'{field}_total'] = len(flow.get(field) or [])
                    snapshot[f'{field}_truncated'] = bool(flow.get(field))
            elif compact_snapshot:
                snapshot = dict(flow)
                for field, limit in (("timeline", 20), ("related_alert_ids", 20), ("sample_packets", 1)):
                    values = flow.get(field) or []
                    snapshot[field] = values[-limit:]
                    snapshot[f"{field}_total"] = len(values)
                    snapshot[f"{field}_truncated"] = len(values) > limit
            if not redact_snapshot and not live_summary:
                return self._public_flow(snapshot)
            # Detach nested state before the expensive redaction walk releases the lock.
            snapshot = {
                key: dict(value) if key == 'alert_counts' and type(value) is Counter
                else _detach_summary_value(value)
                for key, value in snapshot.items()
            }
        return redact_sensitive_data(snapshot) if redact_snapshot else snapshot

    def reset(self) -> None:
        with self._lock:
            self._flows.clear()
            self._alert_ids.clear()
            self._conversations.clear()
            self._seen_destinations.clear()
            self._monitor_directions.clear()
            self._monitor_risks.clear()
            self._hot_flows.clear()
            self._cold_count = self._cold_bytes = 0
            self._cold_json_bytes = 0
            self._compacted_total = self._restored_total = self._unpackable_total = 0

    @staticmethod
    def _snapshot_copy(flow):
        if PACKED_FIELD in flow:
            return dict(flow)
        return {key: list(value) if key in ('timeline', 'related_alert_ids', 'sample_packets')
                else dict(value) if key == 'alert_counts' and type(value) is Counter
                else _detach_summary_value(value) for key, value in flow.items()}

    def compact_idle(self, *, hot_target=2048, idle_seconds=120, batch_size=16):
        target = max(1, int(hot_target))
        cutoff = self._clock() - max(0, float(idle_seconds))
        with self._lock:
            candidates = []
            excess = len(self._hot_flows) - target
            for identifier, touched in self._hot_flows.items():
                if len(candidates) >= min(max(1, int(batch_size)), excess) or touched > cutoff:
                    break
                candidates.append(identifier)
        packed = 0
        for identifier in candidates:
            with self._lock:
                original = self._flows.get(identifier)
                touched = self._hot_flows.get(identifier)
                if original is None or touched is None or touched > cutoff or len(self._hot_flows) <= target:
                    continue
                version = original['packets_count']
                snapshot = self._snapshot_copy(original)
            # Compression and JSON traversal must not hold the ingest lock.
            try:
                payload, raw_size = pack_flow(snapshot)
            except (TypeError, ValueError, RecursionError):
                with self._lock:
                    self._unpackable_total += 1
                    if self._flows.get(identifier) is original and identifier in self._hot_flows:
                        self._hot_flows[identifier] = self._clock()
                        self._hot_flows.move_to_end(identifier)
                continue
            with self._lock:
                if self._flows.get(identifier) is not original or original['packets_count'] != version:
                    continue
                stub = {key: _detach_summary_value(value) for key, value in original.items()
                        if key not in DETAIL_FIELDS}
                stub[PACKED_FIELD] = payload
                stub[ALERT_COUNT_FIELD] = len(original.get('related_alert_ids') or [])
                stub[RAW_BYTES_FIELD] = raw_size
                self._flows[identifier] = stub
                self._hot_flows.pop(identifier, None)
                self._alert_ids.pop(identifier, None)
                self._cold_count += 1
                self._cold_bytes += len(payload)
                self._cold_json_bytes += raw_size
                self._compacted_total += 1
                packed += 1
        return packed

    def memory_stats(self):
        with self._lock:
            return dict(total_flows=len(self._flows), hot_flows=len(self._hot_flows),
                        compressed_flows=self._cold_count, compressed_bytes=self._cold_bytes,
                        cold_json_bytes=self._cold_json_bytes,
                        compactions_total=self._compacted_total, restorations_total=self._restored_total,
                        unsupported_compactions_total=self._unpackable_total)

    def monitoring_summary(self) -> dict[str, Any]:
        # Polling must not sort/copy every flow while holding the ingest lock.
        with self._lock:
            return {
                "total_flows": len(self._flows),
                "active_flows": len(self._flows),
                "external_flows": self._monitor_directions["outbound"] + self._monitor_directions["inbound"],
                "internal_flows": self._monitor_directions["internal"],
                "risk_distribution": dict(self._monitor_risks),
            }

    def list_flows(self, **filters: Any) -> list[dict[str, Any]]:
        with self._lock:
            selected = self._list_flows_locked(**filters)
            snapshots = [self._snapshot_copy(flow) for flow in selected]
        return [self._public_flow(flow) for flow in snapshots]

    def _list_flows_locked(self, **filters: Any) -> list[dict[str, Any]]:
        flows = list(self._flows.values())
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
            flows = [flow for flow in flows if alert_count(flow)]
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
                alert_count(item)
                if sort_key == "related_alert_ids"
                else item.get(sort_key) or 0
            ),
            reverse=True,
        )
        return flows[: max(1, min(int(filters.get("limit") or 100), 500))]

    def get_flow(self, flow_id: str) -> dict[str, Any] | None:
        with self._lock:
            flow = self._flows.get(flow_id)
            snapshot = self._snapshot_copy(flow) if flow else None
        return self._public_flow(snapshot) if snapshot is not None else None

    def snapshot_flows(self, identifiers: list[str]) -> list[dict[str, Any]]:
        snapshots = []
        for offset in range(0, len(identifiers), 16):
            with self._lock:
                flows = [self._flows.get(identifier) for identifier in identifiers[offset:offset + 16]]
                if any(flow is None for flow in flows):
                    raise RuntimeError("Live flow snapshot disappeared before persistence")
                # History entries are append-only; capture their membership under the lock.
                chunk = [self._snapshot_copy(flow) for flow in flows]
            snapshots.extend(redact_sensitive_data([expand_flow(flow) for flow in chunk]))
        return snapshots

    def timeline(self, flow_id: str) -> list[dict[str, Any]]:
        flow = self.get_flow(flow_id)
        return list(flow.get("timeline") or []) if flow else []

    def conversations(self) -> list[dict[str, Any]]:
        with self._lock:
            items = []
            for conversation_id, flow_ids in self._conversations.items():
                flows = [self._flows[item] for item in flow_ids]
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

    def summary(self, *, compact_top: bool = False) -> dict[str, Any]:
        # Aggregate scalar snapshots; copy histories only for the returned top ten.
        with self._lock:
            total_conversations = len(self._conversations)
            selected = sorted(
                self._flows.values(), key=lambda item: item.get("last_seen") or 0,
                reverse=True,
            )
            flows = [
                {**{field: item.get(field) for field in (
                    "app_protocol", "transport", "risk_level", "direction",
                    "bytes_total", "dst_ip", "packets_count", "dst_port", "service_name",
                )}, "alert_count": alert_count(item)}
                for item in selected
            ]
            top_snapshots = [self._snapshot_copy(item) for item in
                             sorted(selected, key=lambda item: item['risk_score'], reverse=True)[:10]]
        top_risky_flows = []
        if compact_top:
            for stored in top_snapshots:
                item = dict(expand_flow(stored))
                for field, limit in (("timeline", 20), ("related_alert_ids", 20), ("sample_packets", 1)):
                    values = item.get(field) or []
                    item[field] = values[-limit:]
                    item[f"{field}_total"] = len(values)
                    item[f"{field}_truncated"] = len(values) > limit
                top_risky_flows.append(self._public_flow(item))
        else:
            top_risky_flows = [self._public_flow(item) for item in top_snapshots]
        protocol_counts = Counter(item["app_protocol"] if item["app_protocol"] != "UNKNOWN" else item["transport"] for item in flows)
        risk_counts = Counter(item["risk_level"] for item in flows)
        directions = Counter(item["direction"] for item in flows)
        bytes_by_protocol = Counter()
        alerts_by_protocol = Counter()
        destinations = Counter()
        ports = Counter()
        for item in flows:
            protocol_label = item["app_protocol"] if item["app_protocol"] != "UNKNOWN" else item["transport"]
            bytes_by_protocol[protocol_label] += item["bytes_total"]
            alerts_by_protocol[protocol_label] += item["alert_count"]
            destinations[str(item.get("dst_ip") or "-")] += item["packets_count"]
            ports[int(item.get("dst_port") or 0)] += item["packets_count"]
        return {
            "total_flows": len(flows),
            "total_conversations": total_conversations,
            "bytes_total": sum(item["bytes_total"] for item in flows),
            "unknown_destinations": len({item["dst_ip"] for item in flows if not item.get("service_name") or str(item["service_name"]).lower().startswith("unknown")}),
            "active_flows": len(flows),
            "external_flows": directions["outbound"] + directions["inbound"],
            "internal_flows": directions["internal"],
            "top_protocols": _counter_items(protocol_counts, "protocol"),
            "top_destinations": _counter_items(destinations, "destination"),
            "top_ports": _counter_items(ports, "port"),
            "top_risky_flows": top_risky_flows,
            "risk_distribution": dict(risk_counts),
            "bytes_by_protocol": dict(bytes_by_protocol),
            "alerts_by_protocol": dict(alerts_by_protocol),
        }

    @staticmethod
    def _public_flow(flow: dict[str, Any]) -> dict[str, Any]:
        public = expand_flow(flow) if PACKED_FIELD in flow else deepcopy(flow)
        public["alert_counts"] = dict(public.get("alert_counts") or {})
        return public


def _counter_items(counter: Counter, key: str, limit: int = 10) -> list[dict[str, Any]]:
    return [{key: value, "count": count} for value, count in counter.most_common(limit)]


__all__ = ["FlowEngine", "direction_for", "flow_id_for", "flow_key"]
