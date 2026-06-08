from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.app.services.capture_policy import current_capture_policy
from core.display_filter import apply_display_filter
from core.dns_intelligence import analyze_dns_packets
from core.expert_info import flow_expert_items, packet_expert_items
from core.flow_engine import flow_id_for
from core.http_intelligence import analyze_http_packets
from core.packet_dissector import dissect_packet
from core.privacy_redaction import redact_sensitive_data
from core.stream_reassembler import reconstruct_stream
from core.tcp_analysis import analyze_tcp_packets
from core.tls_intelligence import analyze_tls_packets


class PacketDetailService:
    def __init__(
        self, history_service: Any, sniffer_service: Any, flow_service: Any
    ) -> None:
        self.history = history_service
        self.sniffer = sniffer_service
        self.flows = flow_service

    async def packet(self, packet_id: str) -> dict[str, Any] | None:
        return await self.history.aget_packet_detail(packet_id)

    async def details(self, packet_id: str) -> dict[str, Any] | None:
        packet = await self.packet(packet_id)
        if not packet:
            return None
        context = await self.history.aget_packet_flow_context(packet_id) or {}
        alert_ids = [
            str(item.get("id"))
            for item in context.get("related_alerts", [])
            if item.get("id")
        ]
        mode = current_capture_policy().mode
        return dissect_packet(packet, capture_mode=mode, related_alert_ids=alert_ids)

    async def hex_view(self, packet_id: str) -> dict[str, Any] | None:
        details = await self.details(packet_id)
        return details.get("hex") if details else None

    def _flow_packets(self, flow_id: str) -> list[dict[str, Any]]:
        selected = []
        for packet in self.sniffer.recent_packets():
            if flow_id_for(packet) == flow_id:
                selected.append(packet)
        return selected

    def flow_stream(self, flow_id: str) -> dict[str, Any] | None:
        flow = self.flows.get_flow(flow_id)
        if not flow:
            return None
        return reconstruct_stream(
            self._flow_packets(flow_id),
            flow_id=flow_id,
            protocol=str(flow.get("app_protocol") or "UNKNOWN"),
            capture_mode=current_capture_policy().mode,
        )

    def conversation_stream(self, conversation_id: str) -> dict[str, Any] | None:
        conversation = self.flows.get_conversation(conversation_id)
        if not conversation:
            return None
        packets = [
            packet
            for flow_id in conversation.get("flow_ids", [])
            for packet in self._flow_packets(flow_id)
        ]
        protocols = conversation.get("protocols") or ["UNKNOWN"]
        return reconstruct_stream(
            packets,
            flow_id=conversation_id,
            protocol="/".join(protocols),
            capture_mode=current_capture_policy().mode,
        )

    def expert_summary(self) -> dict[str, Any]:
        packet_items = [
            item
            for packet in self.sniffer.recent_packets()
            for item in packet_expert_items(packet, flow_id_for(packet))
        ]
        flow_items = [
            item
            for flow in self.flows.list_flows(limit=500)
            for item in flow_expert_items(flow)
        ]
        items = packet_items + flow_items
        categories: dict[str, int] = {}
        for item in items:
            category = str(item.get("category") or "other")
            categories[category] = categories.get(category, 0) + 1
        return redact_sensitive_data(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total": len(items),
                "items": items,
                "severity": {
                    level: sum(1 for item in items if item["severity"] == level)
                    for level in ("note", "chat", "warn", "error")
                },
                "by_category": categories,
                "top_items": items[:20],
                "top_affected_flows": [
                    item for item in items if item.get("related_flow_id")
                ][:20],
                "recommended_actions": sorted(
                    {
                        str(item.get("recommended_action"))
                        for item in items
                        if item.get("recommended_action")
                    }
                ),
            }
        )

    def protocol_intelligence(self) -> dict[str, Any]:
        packets = self.sniffer.recent_packets()
        return redact_sensitive_data(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "protocols": self.flows.protocols_summary(),
                "tcp": analyze_tcp_packets(packets),
                "dns": analyze_dns_packets(packets),
                "http": analyze_http_packets(packets),
                "tls": analyze_tls_packets(packets),
            }
        )

    def search(self, query: str, limit: int = 100) -> dict[str, Any]:
        safe_query = str(redact_sensitive_data(query or "")).strip().lower()
        if not safe_query:
            return {"query": "", "items": [], "total": 0}
        fields = (
            "id",
            "src",
            "dst",
            "sport",
            "dport",
            "proto",
            "app_protocol",
            "summary",
            "risk_level",
            "expert_category",
            "expert_severity",
            "dns_qname",
            "http_host",
            "http_path",
            "tls_sni",
        )
        items = []
        for packet in self.sniffer.recent_packets():
            safe = redact_sensitive_data(packet)
            haystack = " ".join(str(safe.get(field) or "") for field in fields).lower()
            if safe_query in haystack:
                items.append(
                    {
                        field: safe.get(field)
                        for field in fields
                        if safe.get(field) not in (None, "")
                    }
                )
        return redact_sensitive_data(
            {
                "query": safe_query,
                "items": items[: max(1, min(limit, 500))],
                "total": len(items),
            }
        )

    def packet_report(self, display_filter: str = "") -> dict[str, Any]:
        packets = self.sniffer.recent_packets()
        if display_filter:
            packets = apply_display_filter(packets, display_filter)
        protocols: dict[str, int] = {}
        for packet in packets:
            key = str(packet.get("app_protocol") or packet.get("proto") or "UNKNOWN")
            protocols[key] = protocols.get(key, 0) + 1
        expert = self.expert_summary()
        return redact_sensitive_data(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_packets": len(packets),
                "top_protocols": sorted(
                    (
                        {"protocol": key, "count": count}
                        for key, count in protocols.items()
                    ),
                    key=lambda item: item["count"],
                    reverse=True,
                )[:10],
                "malformed_packets": sum(
                    1 for item in expert["items"] if item["category"] == "malformed"
                ),
                "expert_warnings": expert["severity"],
                "top_risky_flows": self.flows.summary()["top_risky_flows"],
                "protocol_distribution": protocols,
                "display_filter": display_filter or None,
                "recommended_actions": [
                    "Review error and warning expert items.",
                    "Validate unusual protocols and destinations.",
                    "Keep inspection within authorized capture scope.",
                ],
            }
        )
