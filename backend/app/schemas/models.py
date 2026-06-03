from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ServiceState(BaseModel):
    model_config = ConfigDict(extra="allow")

    running: bool = False
    iface: str | None = None
    packet_count: int = 0
    total_packets: int = 0
    total_alerts: int = 0
    observability: dict[str, Any] = Field(default_factory=dict)


class PacketItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: int | str | None = None
    ts: str | None = None
    src: str | None = None
    dst: str | None = None
    proto: str | None = None
    sport: int | None = None
    dport: int | None = None
    length: int | None = None
    summary: str | None = None
    app_protocol: str | None = None
    app_category: str | None = None
    l7: str | None = None
    pid: int | None = None
    process_name: str | None = None
    parent_pid: int | None = None
    parent_process_name: str | None = None
    executable_path: str | None = None
    attribution_confidence: str | None = None
    attribution_reason_unavailable: str | None = None


class AlertItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: int | str | None = None
    ts: str | None = None
    src: str | None = None
    dst: str | None = None
    proto: str | None = None
    attack_type: str | None = None
    score: float | None = None
    detail: str | None = None
    app_protocol: str | None = None
    app_category: str | None = None
    pid: int | None = None
    process_name: str | None = None
    parent_pid: int | None = None
    parent_process_name: str | None = None
    executable_path: str | None = None
    attribution_confidence: str | None = None
    attribution_reason_unavailable: str | None = None


class PacketFlowContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    flow_id: str | None = None
    conversation_key: str | None = None
    flow_packets_total: int = 0
    flow_alerts_total: int = 0
    flow_bytes_in: int = 0
    flow_bytes_out: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    duration_ms: int = 0
    same_peer_packets_total: int = 0
    same_peer_alerts_total: int = 0
    same_port_packets_total: int = 0
    sample_packets: int = 0
    sample_alerts: int = 0
    previous_packet_delta_ms: int | None = None
    behavior_labels: list[str] = Field(default_factory=list)
    behavior_evidence: list[dict[str, Any]] = Field(default_factory=list)
    stream_context: dict[str, Any] = Field(default_factory=dict)
    process_correlation: dict[str, Any] = Field(default_factory=dict)
    host_correlation: dict[str, Any] = Field(default_factory=dict)
    port_correlation: dict[str, Any] = Field(default_factory=dict)
    conversation_clusters: list[dict[str, Any]] = Field(default_factory=list)
    related_flows: list[dict[str, Any]] = Field(default_factory=list)
    same_remote_packets: list[PacketItem] = Field(default_factory=list)
    same_remote_alerts: list[AlertItem] = Field(default_factory=list)
    alert_correlation: dict[str, Any] = Field(default_factory=dict)
    root_cause_groups: list[dict[str, Any]] = Field(default_factory=list)
    related_packets: list[PacketItem] = Field(default_factory=list)
    related_alerts: list[AlertItem] = Field(default_factory=list)
    source: str | None = None


class AlertInvestigationContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    alert_id: int | str | None = None
    packet_id: int | str | None = None
    linked_packet_id: int | str | None = None
    flow_id: str | None = None
    conversation_key: str | None = None
    flow_packets_total: int = 0
    flow_alerts_total: int = 0
    linked_packet: PacketItem | None = None
    linked_packet_summary: PacketItem | None = None
    related_flows: list[dict[str, Any]] = Field(default_factory=list)
    same_remote_packets: list[PacketItem] = Field(default_factory=list)
    same_remote_alerts: list[AlertItem] = Field(default_factory=list)
    alert_correlation: dict[str, Any] = Field(default_factory=dict)
    root_cause_groups: list[dict[str, Any]] = Field(default_factory=list)
    behavior_labels: list[str] = Field(default_factory=list)
    behavior_evidence: list[dict[str, Any]] = Field(default_factory=list)
    stream_context: dict[str, Any] = Field(default_factory=dict)
    process_correlation: dict[str, Any] = Field(default_factory=dict)
    host_correlation: dict[str, Any] = Field(default_factory=dict)
    port_correlation: dict[str, Any] = Field(default_factory=dict)
    conversation_clusters: list[dict[str, Any]] = Field(default_factory=list)
    related_packets: list[PacketItem] = Field(default_factory=list)
    related_alerts: list[AlertItem] = Field(default_factory=list)
    source: str | None = None


class PaginatedPacketsResponse(BaseModel):
    items: list[PacketItem]
    total: int
    limit: int
    offset: int
    source: str
    query_ms: float | None = None
    observability: dict[str, Any] = Field(default_factory=dict)


class PaginatedAlertsResponse(BaseModel):
    items: list[AlertItem]
    total: int
    limit: int
    offset: int
    source: str
    query_ms: float | None = None
    observability: dict[str, Any] = Field(default_factory=dict)


class DashboardResponse(BaseModel):
    state: ServiceState
    top_sources: list[dict[str, Any]] = Field(default_factory=list)
    top_destinations: list[dict[str, Any]] = Field(default_factory=list)
    top_protocols: list[dict[str, Any]] = Field(default_factory=list)
    top_processes: list[dict[str, Any]] = Field(default_factory=list)
    top_remotes: list[dict[str, Any]] = Field(default_factory=list)
    top_conversations: list[dict[str, Any]] = Field(default_factory=list)
    recent_alerts: list[AlertItem] = Field(default_factory=list)
    recent_packets: list[PacketItem] = Field(default_factory=list)
    local_token_required: bool | None = None
    observability: dict[str, Any] = Field(default_factory=dict)


class StatusResponse(BaseModel):
    ok: bool
    sniffer: ServiceState
    local_token_required: bool
    observability: dict[str, Any] = Field(default_factory=dict)


class SettingsPayload(BaseModel):
    iface: str | None = None
    ids_ml_threshold: float | None = None
    tr_timeout: float | None = None
    tr_mode: str | None = None
    auto_block: bool | None = None
    persist_logs: bool | None = None
    whitelist_ips: str | None = None
    retention_minutes: int | None = None
    payload_capture_enabled: bool | None = None
    alert_only_mode: bool | None = None
    safe_use_policy_accepted: bool | None = None
    remote_dashboard_allowlist: str | None = None


class EventEnvelope(BaseModel):
    version: int = 1
    type: str
    timestamp: str
    payload: dict[str, Any]
