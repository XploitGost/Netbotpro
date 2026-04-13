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


class EventEnvelope(BaseModel):
    version: int = 1
    type: str
    timestamp: str
    payload: dict[str, Any]
