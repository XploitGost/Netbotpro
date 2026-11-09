"""Ordered delivery boundary, independent of capture, detection and API lifecycle."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol


Row = dict[str, Any]


@dataclass(frozen=True, slots=True)
class AnalyzedPacket:
    """Single-owner handoff; nested rows remain mutable and are NOT certified safe.

    Analysis stops mutating these rows after handoff. Retaining/async destinations
    still own their existing detachment and redaction responsibilities.
    """

    packet: Row
    flow: Row | None
    flow_key: str
    alerts: list[Row]
    expert_items: list[Row]
    incidents: list[Row]


class AppendView(Protocol):
    def __call__(self, category: str, payload: Row, *, flow_key: str,
                 timestamp: str, source: str, return_record: bool) -> Any: ...


@dataclass(frozen=True, slots=True)
class DeliveryPorts:
    add_packet: Callable[[Row], None]
    add_alerts: Callable[[list[Row]], None]
    append_view: AppendView
    append_incident_view: AppendView
    submit_flow_view: Callable[[Row], None]
    persist_packet: Callable[[Row, list[Row]], None]
    persist_flow: Callable[[Row], None]
    publish_packet: Callable[[Row], None]
    publish_alerts: Callable[[list[Row]], None]
    publish_incidents: Callable[[list[Row]], None]


class PacketDelivery:
    """Fan out synchronously in legacy order; propagate failures to the caller.

    Completion is not a durable commit receipt: persistence ports may enqueue.
    This boundary creates no threads, queues, retry policy or acknowledgement.
    """

    def __init__(self, ports: DeliveryPorts) -> None:
        self._ports = ports

    def deliver(self, result: AnalyzedPacket) -> None:
        ports = self._ports
        packet, flow = result.packet, result.flow
        ports.add_packet(packet)
        ports.add_alerts(result.alerts)
        ports.append_view("packet", packet, flow_key=result.flow_key,
                          timestamp=str(packet.get("ts") or packet.get("timestamp") or ""),
                          source="live_capture", return_record=False)
        if isinstance(flow, dict):
            live_flow = dict(flow)
            for field in ("timeline", "related_alert_ids"):
                values = flow.get(field) or []
                live_flow[field] = values[-20:]
                live_flow[f"{field}_total"] = flow.get(f"{field}_total", len(values))
                live_flow[f"{field}_truncated"] = flow.get(f"{field}_truncated", len(values) > 20)
            ports.submit_flow_view(live_flow)
        for alert in result.alerts:
            ports.append_view("alert", alert, flow_key=result.flow_key,
                              timestamp=str(alert.get("ts") or alert.get("timestamp") or ""),
                              source="detection_engine", return_record=False)
        for item in result.expert_items:
            ports.append_view("expert_info", item, flow_key=result.flow_key,
                              timestamp=str(item.get("last_seen") or ""),
                              source="expert_info", return_record=False)
        for incident in result.incidents:
            ports.append_incident_view("incident", incident, flow_key=result.flow_key,
                                       timestamp=str(incident.get("last_seen") or ""),
                                       source="incident_correlation", return_record=False)
        ports.persist_packet(packet, result.alerts)
        if isinstance(flow, dict):
            ports.persist_flow(flow)
        ports.publish_packet(packet)
        ports.publish_alerts(result.alerts)
        ports.publish_incidents(result.incidents)
