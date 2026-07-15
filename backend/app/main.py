from __future__ import annotations

import csv
import io
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import (
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.schemas import (
    AlertInvestigationContext,
    AlertItem,
    DashboardResponse,
    PacketFlowContext,
    PacketItem,
    PaginatedAlertsResponse,
    PaginatedPacketsResponse,
    SettingsPayload,
    StatusResponse,
)
from backend.app.security import (
    allowed_origins,
    enforce_rate_limit,
    ensure_within_directory,
    extract_websocket_token,
    is_allowed_websocket_origin,
    is_local_token_enabled,
    is_trusted_websocket_client,
    require_local_token,
    require_trusted_client,
    validate_block_ip,
    validate_ip,
    validate_report_download_path,
)
from backend.app.services.agent_demo import seed_demo_data
from backend.app.services.agent_registry import AgentRegistry
from backend.app.services.audit_service import audit_event
from backend.app.services.capture_policy import (
    current_capture_policy,
    enforce_capture_policy,
)
from backend.app.services.event_bus import EventBus
from backend.app.services.export_service import ExportService
from backend.app.services.flow_service import FlowService
from backend.app.services.history_service import HistoryRepositoryError, HistoryService
from backend.app.services.investigation_export_service import InvestigationExportService
from backend.app.services.monitoring_service import build_monitoring_metrics
from backend.app.services.packet_detail_service import PacketDetailService
from backend.app.services.report_service import ReportService
from backend.app.services.saved_filter_service import SavedFilterService
from backend.app.services.settings_service import get_settings, update_settings
from backend.app.services.sniffer_service import (
    CaptureStartUnavailableError,
    SnifferService,
)
from backend.app.services.traceroute_service import TracerouteService
from core.capture import SystemCaptureProvider

ensure_project_root_on_path()

from core.display_filter import DisplayFilterError  # noqa: E402
from core.display_filter import apply_display_filter, filter_help, filter_suggestions
from core.expert_info import flow_expert_items  # noqa: E402
from core.expert_info import packet_expert_items
from core.firewall_tools import block_ip  # noqa: E402
from core.flow_engine import flow_id_for  # noqa: E402
from log_manager import LOG_DIR  # noqa: E402

event_bus = EventBus()
capture_provider = SystemCaptureProvider()
flow_service = FlowService()
sniffer_service = SnifferService(
    event_bus,
    capture_provider=capture_provider,
    flow_service=flow_service,
)
traceroute_service = TracerouteService()
export_service = ExportService()
investigation_export_service = InvestigationExportService()
history_service = HistoryService(sniffer_service)
report_service = ReportService()
agent_registry = AgentRegistry()
packet_detail_service = PacketDetailService(
    history_service, sniffer_service, flow_service
)
saved_filter_service = SavedFilterService()
logger = logging.getLogger("netbotpro.api")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
MAX_PCAP_UPLOAD_BYTES = 50 * 1024 * 1024
ALLOWED_PCAP_SUFFIXES = {".pcap", ".pcapng"}


def _observability_snapshot() -> dict[str, Any]:
    return {
        "event_bus": event_bus.stats(),
        "event_aggregator": event_bus.event_aggregator_stats(),
        "websocket": event_bus.websocket_stats(),
        "history": history_service.metrics(),
        "packet_queue": sniffer_service.packet_queue_stats(),
        "flow_worker_pool": sniffer_service.flow_worker_pool_stats(),
        "live_ring_buffer": sniffer_service.live_ring_buffer_stats(),
        "service_attribution": sniffer_service.service_attribution_stats(),
        "persistence": sniffer_service.persistence_stats(),
        "auto_block": sniffer_service.auto_block_stats(),
    }


def _load_pcap_analyzer():
    try:
        from core.offline_analyzer import analyze_pcap_file
    except Exception as exc:
        logger.exception("offline_analysis_unavailable")
        raise HTTPException(
            status_code=503,
            detail="Offline PCAP analysis is unavailable in this runtime",
        ) from exc
    return analyze_pcap_file


def _actor_from_request(request: Request | None) -> str:
    return request.client.host if request and request.client else "unknown"


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    event_bus.close()
    sniffer_service.close()


app = FastAPI(
    title="NetBotPro API",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def api_root() -> dict[str, Any]:
    return {
        "name": "NetBotPro API",
        "status": "/api/status",
        "dashboard": "/api/dashboard",
        "websocket": "/ws/events",
    }


@app.middleware("http")
async def log_requests(request: Request, call_next):
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception(
            "request_failed method=%s path=%s", request.method, request.url.path
        )
        raise
    duration_ms = (time.perf_counter() - started) * 1000.0
    logger.info(
        "request method=%s path=%s status=%s duration_ms=%.2f client=%s",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
        request.client.host if request.client else "unknown",
    )
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


@app.get("/api/status")
def api_status(_: None = Depends(require_trusted_client)) -> dict[str, Any]:
    return {
        "ok": True,
        "sniffer": sniffer_service.get_state(),
        "observability": _observability_snapshot(),
        "local_token_required": is_local_token_enabled(),
        "capture_policy": current_capture_policy().to_public_dict(),
    }


@app.get("/api/monitoring/metrics")
def api_monitoring_metrics(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return build_monitoring_metrics(
        sniffer_state=sniffer_service.get_state(),
        observability=_observability_snapshot(),
        flow_summary=flow_service.summary(),
    )


@app.get("/api/live/recent")
def api_live_recent(
    type: str = "all",
    limit: int | None = None,
    flow_key: str = "",
    since: str | None = None,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    try:
        return sniffer_service.recent_live_records(
            type,
            limit=limit,
            flow_key=flow_key,
            since=since,
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/live/ring/metrics")
def api_live_ring_metrics(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return sniffer_service.live_ring_buffer_stats()


def _agent_headers(
    agent_id: str = Header("", alias="X-NetBot-Agent-Id"),
    agent_token: str = Header("", alias="X-NetBot-Agent-Token"),
) -> tuple[str, str]:
    return agent_id.strip(), agent_token.strip()


def _require_known_agent(headers: tuple[str, str] = Depends(_agent_headers)) -> str:
    agent_id, agent_token = headers
    if not agent_id:
        audit_event(
            "agent_auth_failed",
            success=False,
            detail={"reason": "missing_agent_id"},
        )
        raise HTTPException(status_code=403, detail="Missing agent id")
    if not agent_registry.verify(agent_id, agent_token):
        audit_event(
            "agent_auth_failed",
            actor=agent_id,
            success=False,
            detail={"reason": "invalid_agent_token"},
        )
        raise HTTPException(status_code=401, detail="Invalid agent token")
    return agent_id


@app.post("/api/agents/register")
def api_agent_register(
    payload: dict[str, Any],
    headers: tuple[str, str] = Depends(_agent_headers),
) -> dict[str, Any]:
    header_agent_id, agent_token = headers
    payload_agent_id = str(payload.get("agent_id") or "").strip()
    if header_agent_id and payload_agent_id and header_agent_id != payload_agent_id:
        audit_event(
            "agent_register_failed",
            actor=header_agent_id,
            success=False,
            detail={"reason": "agent_id_mismatch"},
        )
        raise HTTPException(
            status_code=400, detail="Agent id header and payload mismatch"
        )
    if header_agent_id and not payload_agent_id:
        payload = {**payload, "agent_id": header_agent_id}
        payload_agent_id = header_agent_id
    try:
        registered = agent_registry.register(payload, agent_token)
    except PermissionError as exc:
        audit_event(
            "agent_register_failed",
            actor=payload_agent_id or header_agent_id or "unknown",
            success=False,
            detail={"reason": str(exc)},
        )
        raise HTTPException(status_code=401, detail="Invalid agent token") from exc
    except ValueError as exc:
        audit_event(
            "agent_register_failed",
            actor=header_agent_id or "unknown",
            success=False,
            detail={"reason": str(exc)},
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit_event(
        "agent_registered",
        actor=registered.get("agent_id", "unknown"),
        detail={"hostname": registered.get("hostname")},
    )
    return {"ok": True, "agent": registered}


@app.post("/api/agents/heartbeat")
def api_agent_heartbeat(
    payload: dict[str, Any],
    agent_id: str = Depends(_require_known_agent),
) -> dict[str, Any]:
    try:
        agent = agent_registry.heartbeat(agent_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown agent") from exc
    return {"ok": True, "agent": agent}


@app.post("/api/agents/telemetry")
def api_agent_telemetry(
    payload: dict[str, Any],
    agent_id: str = Depends(_require_known_agent),
) -> dict[str, Any]:
    try:
        return agent_registry.telemetry(agent_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown agent") from exc


@app.get("/api/agents")
def api_agents(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> list[dict[str, Any]]:
    return agent_registry.list_agents()


@app.get("/api/agents/overview")
def api_agents_overview(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return agent_registry.overview()


@app.get("/api/agents/alerts/summary")
def api_agents_alerts_summary(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return agent_registry.alerts_summary()


@app.get("/api/agents/risk/summary")
def api_agents_risk_summary(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return agent_registry.risk_summary()


@app.get("/api/agents/reports/fleet-summary")
def api_agents_fleet_summary_report(
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    report = agent_registry.fleet_summary_report()
    audit_event(
        "agent_fleet_report_generated",
        actor=_actor_from_request(request),
        detail={
            "format": "json",
            "total_agents": report.get("total_agents", 0),
        },
    )
    return report


@app.get("/api/agents/reports/fleet-summary.csv")
def api_agents_fleet_summary_report_csv(
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> Response:
    report = agent_registry.fleet_summary_report()
    output = io.StringIO()
    fieldnames = [
        "agent_id",
        "display_name",
        "hostname",
        "status",
        "os",
        "last_seen",
        "cpu_percent",
        "memory_percent",
        "disk_percent",
        "capture_running",
        "capture_mode",
        "total_alerts",
        "critical_alerts",
        "risk_score",
        "risk_severity",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(report.get("agents") or [])
    audit_event(
        "agent_fleet_report_generated",
        actor=_actor_from_request(request),
        detail={
            "format": "csv",
            "total_agents": report.get("total_agents", 0),
        },
    )
    return Response(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=agent-fleet-summary.csv"},
    )


@app.post("/api/agents/demo/seed")
def api_agents_seed_demo(
    request: Request,
    payload: dict[str, Any] | None = None,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    global agent_registry

    data = payload or {}
    try:
        count = int(data.get("count", 4))
    except (TypeError, ValueError):
        count = 4
    count = max(1, min(20, count))
    reset = bool(data.get("reset", True))
    storage_path = agent_registry.storage_path
    result = seed_demo_data(storage_path, count=count, reset=reset)
    agent_registry = AgentRegistry(storage_path)
    overview = agent_registry.overview()
    audit_event(
        "agent_demo_seeded",
        actor=_actor_from_request(request),
        detail={
            "created_agents": result.get("created_agents", 0),
            "reset": reset,
        },
    )
    return {
        **result,
        "overview": overview,
        "agents": agent_registry.list_agents(),
    }


@app.get("/api/agents/{agent_id}")
def api_agent_detail(
    agent_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    agent = agent_registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@app.get("/api/agents/{agent_id}/telemetry")
def api_agent_telemetry_history(
    agent_id: str,
    range: str = "24h",
    limit: int = 20,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    agent = agent_registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {
        "agent": agent,
        "items": agent_registry.get_telemetry(
            agent_id,
            limit=limit,
            range_name=range,
        ),
    }


@app.get("/api/agents/{agent_id}/health/history")
def api_agent_health_history(
    agent_id: str,
    range: str = "24h",
    limit: int = 200,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    agent = agent_registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {
        "agent": agent,
        "items": agent_registry.history(agent_id, "health", range, limit),
    }


@app.get("/api/agents/{agent_id}/alerts/history")
def api_agent_alerts_history(
    agent_id: str,
    range: str = "24h",
    limit: int = 200,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    agent = agent_registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {
        "agent": agent,
        "items": agent_registry.history(agent_id, "alerts", range, limit),
    }


@app.get("/api/agents/{agent_id}/risk/history")
def api_agent_risk_history(
    agent_id: str,
    range: str = "24h",
    limit: int = 200,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    agent = agent_registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {
        "agent": agent,
        "items": agent_registry.history(agent_id, "risk", range, limit),
    }


@app.get("/api/settings", response_model=SettingsPayload)
def api_get_settings(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return get_settings()


@app.get("/api/flows")
def api_flows(
    protocol: str = "",
    risk: str = "",
    src_ip: str = "",
    dst_ip: str = "",
    direction: str = "",
    port: int = 0,
    has_alerts: bool = False,
    filter: str = "",
    since: str = "",
    limit: int = 100,
    sort: str = "last_seen",
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    items = flow_service.list_flows(
        protocol=protocol,
        risk=risk,
        src_ip=src_ip,
        dst_ip=dst_ip,
        direction=direction,
        port=port,
        has_alerts=has_alerts,
        since=since,
        limit=limit,
        sort=sort,
    )
    try:
        if filter:
            items = apply_display_filter(items, filter)
    except DisplayFilterError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"items": items, "total": len(items)}


@app.get("/api/flows/summary")
def api_flows_summary(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return flow_service.summary()


@app.get("/api/flows/top")
def api_flows_top(
    limit: int = 10,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> list[dict[str, Any]]:
    return flow_service.list_flows(sort="risk", limit=limit)


@app.get("/api/flows/{flow_id}")
def api_flow_detail(
    flow_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    flow = flow_service.get_flow(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return flow


@app.get("/api/flows/{flow_id}/timeline")
def api_flow_timeline(
    flow_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    flow = flow_service.get_flow(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return {"flow_id": flow_id, "items": flow_service.timeline(flow_id)}


@app.get("/api/flows/{flow_id}/stream")
def api_flow_stream(
    flow_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    stream = packet_detail_service.flow_stream(flow_id)
    if not stream:
        raise HTTPException(status_code=404, detail="Flow not found")
    return stream


@app.get("/api/conversations")
def api_conversations(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> list[dict[str, Any]]:
    return flow_service.conversations()


@app.get("/api/conversations/{conversation_id}")
def api_conversation_detail(
    conversation_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    conversation = flow_service.get_conversation(conversation_id)
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conversation


@app.get("/api/conversations/{conversation_id}/stream")
def api_conversation_stream(
    conversation_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    stream = packet_detail_service.conversation_stream(conversation_id)
    if not stream:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return stream


@app.get("/api/expert/packets/{packet_id}")
async def api_expert_packet(
    packet_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    packet = await packet_detail_service.packet(packet_id)
    if not packet:
        raise HTTPException(status_code=404, detail="Packet not found")
    return {"items": packet_expert_items(packet, flow_id_for(packet))}


@app.get("/api/expert/flows/{flow_id}")
def api_expert_flow(
    flow_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    flow = flow_service.get_flow(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return {"items": flow_expert_items(flow)}


@app.get("/api/expert/summary")
def api_expert_summary(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return packet_detail_service.expert_summary()


@app.get("/api/protocols/summary")
def api_protocols_summary(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return flow_service.protocols_summary()


@app.get("/api/protocols/intelligence")
def api_protocol_intelligence(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return packet_detail_service.protocol_intelligence()


@app.get("/api/protocols/{protocol}/summary")
def api_protocol_specific_summary(
    protocol: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    intelligence = packet_detail_service.protocol_intelligence()
    key = protocol.strip().lower()
    if key not in {"tcp", "dns", "http", "tls"}:
        raise HTTPException(
            status_code=404, detail="Protocol intelligence summary not found"
        )
    return intelligence[key]


@app.get("/api/protocols/{protocol}/flows")
def api_protocol_flows(
    protocol: str,
    limit: int = 100,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    items = flow_service.list_flows(protocol=protocol, limit=limit)
    return {"protocol": protocol.upper(), "items": items, "total": len(items)}


@app.get("/api/reports/flows/summary")
def api_flow_summary_report(
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    report = flow_service.report()
    audit_event(
        "flow_summary_report_generated",
        actor=_actor_from_request(request),
        detail={"format": "json", "total_flows": report["total_flows"]},
    )
    return report


@app.get("/api/reports/flows/summary.csv")
def api_flow_summary_report_csv(
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> Response:
    audit_event(
        "flow_summary_report_generated",
        actor=_actor_from_request(request),
        detail={"format": "csv"},
    )
    return Response(
        flow_service.report_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=flow-summary.csv"},
    )


@app.get("/api/reports/packet-analysis/summary")
def api_packet_analysis_report(
    filter: str = "",
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    try:
        return packet_detail_service.packet_report(filter)
    except DisplayFilterError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/reports/expert/summary")
def api_expert_report(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return packet_detail_service.expert_summary()


@app.get("/api/reports/protocols/summary")
def api_protocol_report(
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    report = packet_detail_service.protocol_intelligence()
    audit_event("protocol_summary_report_generated", actor=_actor_from_request(request))
    return report


@app.get("/api/reports/inspection/summary")
def api_inspection_report(
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    report = {
        "packet_analysis": packet_detail_service.packet_report(),
        "protocol_intelligence": packet_detail_service.protocol_intelligence(),
        "expert": packet_detail_service.expert_summary(),
    }
    audit_event(
        "inspection_summary_report_generated", actor=_actor_from_request(request)
    )
    return report


@app.get("/api/interfaces")
def api_interfaces(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return sniffer_service.capture_interfaces()


@app.put("/api/settings", response_model=SettingsPayload)
def api_put_settings(
    payload: dict[str, Any],
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    enforce_rate_limit(request, "settings_update", limit=30, window_sec=60)
    updated = update_settings(payload)
    event_type = (
        "safe_use_accepted"
        if payload.get("safe_use_policy_accepted")
        else "settings_changed"
    )
    audit_event(
        event_type,
        actor=_actor_from_request(request),
        detail={
            "changed_keys": sorted(payload.keys()),
            "capture_mode": updated.get("capture_mode"),
        },
    )
    return updated


@app.post("/api/sniffer/start")
def api_start_sniffer(
    payload: dict[str, Any] | None = None,
    request: Request = None,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    enforce_rate_limit(request, "sniffer_start", limit=12, window_sec=60)
    payload = payload or {}
    iface = payload.get("iface")
    try:
        policy = enforce_capture_policy(payload, request)
        state = sniffer_service.start(iface=iface)
        event_type = "sniffer_started"
        if policy.mode == "full":
            event_type = "full_capture_enabled"
        elif policy.mode == "forensic":
            event_type = "forensic_capture_started"
        state["capture_policy"] = policy.to_public_dict()
        audit_event(
            event_type,
            actor=_actor_from_request(request),
            detail={"iface": state.get("iface"), "capture_mode": policy.mode},
        )
        return state
    except HTTPException as exc:
        policy = current_capture_policy(payload)
        audit_event(
            "sniffer_started",
            actor=_actor_from_request(request),
            success=False,
            detail={
                "reason": str(exc.detail),
                "iface": iface,
                "capture_mode": policy.mode,
            },
        )
        raise
    except CaptureStartUnavailableError as exc:
        logger.warning("capture_start_unavailable detail=%s", exc.detail)
        audit_event(
            "sniffer_started",
            actor=_actor_from_request(request),
            success=False,
            detail={
                "detail": exc.detail,
                "iface": iface,
                "capture_mode": current_capture_policy(payload).mode,
            },
        )
        raise HTTPException(status_code=409, detail=exc.detail) from exc


@app.post("/api/sniffer/stop")
def api_stop_sniffer(
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    enforce_rate_limit(request, "sniffer_stop", limit=20, window_sec=60)
    state = sniffer_service.stop()
    policy = current_capture_policy()
    audit_event(
        "forensic_capture_stopped" if policy.mode == "forensic" else "sniffer_stopped",
        actor=_actor_from_request(request),
        detail={"iface": state.get("iface"), "capture_mode": policy.mode},
    )
    return state


@app.post("/api/session/reset")
def api_reset_session(
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    enforce_rate_limit(request, "session_reset", limit=20, window_sec=60)
    return sniffer_service.reset_session()


@app.get("/api/sniffer/state")
def api_sniffer_state(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    state = sniffer_service.get_state()
    state["observability"] = _observability_snapshot()
    return state


@app.get("/api/packets", response_model=PaginatedPacketsResponse)
async def api_recent_packets(
    src: str = "",
    dst: str = "",
    proto: str = "",
    process: str = "",
    pid: str = "",
    text: str = "",
    only_alerts: bool = False,
    only_remote: bool = False,
    filter: str = "",
    limit: int = 50,
    offset: int = 0,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    try:
        result = await history_service.aget_packets(
            {
                "src": src,
                "dst": dst,
                "proto": proto,
                "process": process,
                "pid": pid,
                "text": text,
                "only_alerts": only_alerts,
                "only_remote": only_remote,
                "limit": limit,
                "offset": offset,
            }
        )
        if filter:
            result["items"] = apply_display_filter(result.get("items", []), filter)
            result["total"] = len(result["items"])
        return result
    except DisplayFilterError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HistoryRepositoryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/packets/filter/help")
def api_packet_filter_help(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return filter_help()


@app.get("/api/packets/filter/suggestions")
def api_packet_filter_suggestions(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return filter_suggestions()


@app.get("/api/filters")
def api_saved_filters(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> list[dict[str, Any]]:
    return saved_filter_service.list()


@app.post("/api/filters")
def api_create_saved_filter(
    payload: dict[str, Any],
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    try:
        return saved_filter_service.create(payload)
    except DisplayFilterError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.patch("/api/filters/{filter_id}")
def api_update_saved_filter(
    filter_id: str,
    payload: dict[str, Any],
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    try:
        return saved_filter_service.update(filter_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Saved filter not found") from exc
    except DisplayFilterError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/filters/{filter_id}")
def api_delete_saved_filter(
    filter_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, bool]:
    try:
        saved_filter_service.delete(filter_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Saved filter not found") from exc
    return {"ok": True}


@app.get("/api/packets/search")
def api_packet_search(
    q: str = "",
    limit: int = 100,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return packet_detail_service.search(q, limit)


@app.get("/api/packets/{packet_id}", response_model=PacketItem)
async def api_packet_detail(
    packet_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    try:
        item = await history_service.aget_packet_detail(packet_id)
    except HistoryRepositoryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if item is None:
        raise HTTPException(status_code=404, detail="Packet not found")
    return item


@app.get("/api/packets/{packet_id}/details")
async def api_packet_dissected_details(
    packet_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    item = await packet_detail_service.details(packet_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Packet not found")
    return item


@app.get("/api/packets/{packet_id}/hex")
async def api_packet_hex(
    packet_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    item = await packet_detail_service.hex_view(packet_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Packet not found")
    return item


@app.get("/api/packets/{packet_id}/expert")
async def api_packet_expert(
    packet_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    packet = await packet_detail_service.packet(packet_id)
    if packet is None:
        raise HTTPException(status_code=404, detail="Packet not found")
    return {"items": packet_expert_items(packet, flow_id_for(packet))}


@app.get("/api/packets/{packet_id}/context", response_model=PacketFlowContext)
async def api_packet_flow_context(
    packet_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    try:
        item = await history_service.aget_packet_flow_context(packet_id)
    except HistoryRepositoryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if item is None:
        raise HTTPException(status_code=404, detail="Packet not found")
    return item


@app.get("/api/dashboard", response_model=DashboardResponse)
def api_dashboard(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    dashboard = sniffer_service.dashboard()
    dashboard["observability"] = _observability_snapshot()
    dashboard["local_token_required"] = is_local_token_enabled()
    return dashboard


@app.get("/api/alerts", response_model=PaginatedAlertsResponse)
async def api_recent_alerts(
    src: str = "",
    dst: str = "",
    attack: str = "",
    proto: str = "",
    process: str = "",
    pid: str = "",
    text: str = "",
    min_score: str = "",
    only_remote: bool = False,
    limit: int = 50,
    offset: int = 0,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    try:
        return await history_service.aget_alerts(
            {
                "src": src,
                "dst": dst,
                "attack": attack,
                "proto": proto,
                "process": process,
                "pid": pid,
                "text": text,
                "min_score": min_score,
                "only_remote": only_remote,
                "limit": limit,
                "offset": offset,
            }
        )
    except HistoryRepositoryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/alerts/{alert_id}", response_model=AlertItem)
async def api_alert_detail(
    alert_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    try:
        item = await history_service.aget_alert_detail(alert_id)
    except HistoryRepositoryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if item is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return item


@app.get("/api/alerts/{alert_id}/context", response_model=AlertInvestigationContext)
async def api_alert_context(
    alert_id: str,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    try:
        item = await history_service.aget_alert_context(alert_id)
    except HistoryRepositoryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if item is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return item


@app.post("/api/firewall/block")
def api_block_ip(
    payload: dict[str, Any],
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    enforce_rate_limit(request, "firewall_block", limit=10, window_sec=60)
    ip = validate_block_ip(str(payload.get("ip") or ""))
    audit_event(
        "firewall_block_requested",
        actor=_actor_from_request(request),
        detail={"target": ip, "capture_mode": current_capture_policy().mode},
    )
    ok = block_ip(ip)
    if not ok:
        raise HTTPException(status_code=409, detail=f"Failed to block {ip}")
    return {"ok": True, "ip": ip}


@app.post("/api/traceroute")
def api_traceroute(
    payload: dict[str, Any],
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    enforce_rate_limit(request, "traceroute", limit=12, window_sec=60)
    audit_event(
        "traceroute_requested",
        actor=_actor_from_request(request),
        detail={
            "target": str(payload.get("target") or ""),
            "capture_mode": current_capture_policy().mode,
        },
    )
    return traceroute_service.run(payload)


@app.get("/api/traceroute/history")
def api_traceroute_history(
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> list[dict[str, Any]]:
    enforce_rate_limit(request, "traceroute_history", limit=60, window_sec=60)
    return traceroute_service.history()


@app.post("/api/exports/session")
def api_export_session(
    payload: dict[str, Any],
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    enforce_rate_limit(request, "export_session", limit=20, window_sec=60)
    history = traceroute_service.history()
    try:
        result = export_service.export_session(
            kind=str(payload.get("format") or "zip"),
            packet_rows=sniffer_service.recent_packets(),
            alert_rows=sniffer_service.recent_alerts(),
            traceroute_rows=(history[0].get("hops", []) if history else []),
        )
        audit_event(
            "report_generated",
            actor=_actor_from_request(request),
            detail={
                "kind": result.get("format"),
                "path": result.get("path"),
                "capture_mode": current_capture_policy().mode,
            },
        )
        return result
    except ValueError as exc:
        audit_event(
            "report_generated",
            actor=_actor_from_request(request),
            success=False,
            detail={"detail": str(exc), "capture_mode": current_capture_policy().mode},
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/exports/investigation")
def api_export_investigation(
    payload: dict[str, Any],
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    enforce_rate_limit(request, "export_investigation", limit=20, window_sec=60)
    try:
        result = investigation_export_service.export_report(payload)
        audit_event(
            "report_generated",
            actor=_actor_from_request(request),
            detail={
                "kind": result.get("kind"),
                "path": result.get("path"),
                "capture_mode": current_capture_policy().mode,
            },
        )
        return result
    except ValueError as exc:
        audit_event(
            "report_generated",
            actor=_actor_from_request(request),
            success=False,
            detail={"detail": str(exc), "capture_mode": current_capture_policy().mode},
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/exports/download")
def api_export_download(
    path: str,
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> FileResponse:
    enforce_rate_limit(request, "export_download", limit=30, window_sec=60)
    safe_name = validate_report_download_path(path)
    file_path = Path(ensure_within_directory(str(LOG_DIR), safe_name))
    if not file_path.exists() or not file_path.is_file():
        audit_event(
            "export_downloaded",
            actor=_actor_from_request(request),
            success=False,
            detail={"path": safe_name, "capture_mode": current_capture_policy().mode},
        )
        raise HTTPException(status_code=404, detail="Export not found")
    audit_event(
        "export_downloaded",
        actor=_actor_from_request(request),
        detail={"path": safe_name, "capture_mode": current_capture_policy().mode},
    )
    return FileResponse(
        file_path, filename=file_path.name, headers={"Cache-Control": "no-store"}
    )


@app.get("/api/exports/raw-pcap")
def api_raw_pcap_download(
    path: str,
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> FileResponse:
    enforce_rate_limit(request, "raw_pcap_download", limit=8, window_sec=60)
    policy = enforce_capture_policy(
        {"capture_mode": current_capture_policy().mode}, request
    )
    if policy.mode not in {"full", "forensic"}:
        audit_event(
            "raw_pcap_export_downloaded",
            actor=_actor_from_request(request),
            success=False,
            detail={"reason": "metadata_mode", "capture_mode": policy.mode},
        )
        raise HTTPException(
            status_code=403,
            detail="Raw PCAP export is only available in full or forensic capture mode",
        )
    safe_name = Path(str(path or "").strip()).name
    if not safe_name or safe_name != str(path or "").strip():
        raise HTTPException(status_code=400, detail="Unsafe raw PCAP path")
    if Path(safe_name).suffix.lower() not in {".pcap", ".pcapng"}:
        audit_event(
            "raw_pcap_export_downloaded",
            actor=_actor_from_request(request),
            success=False,
            detail={
                "reason": "unsupported_type",
                "path": safe_name,
                "capture_mode": policy.mode,
            },
        )
        raise HTTPException(
            status_code=400, detail="Raw export must be a .pcap or .pcapng artifact"
        )
    file_path = Path(ensure_within_directory(str(LOG_DIR), safe_name))
    if not file_path.exists() or not file_path.is_file():
        audit_event(
            "raw_pcap_export_downloaded",
            actor=_actor_from_request(request),
            success=False,
            detail={
                "reason": "not_found",
                "path": safe_name,
                "capture_mode": policy.mode,
            },
        )
        raise HTTPException(status_code=404, detail="Raw PCAP artifact not found")
    audit_event(
        "raw_pcap_export_downloaded",
        actor=_actor_from_request(request),
        detail={"path": safe_name, "capture_mode": policy.mode},
    )
    return FileResponse(
        file_path,
        filename=file_path.name,
        headers={
            "Cache-Control": "no-store",
            "X-NetBot-Warning": "Raw PCAP may contain sensitive data",
        },
    )


@app.get("/api/reports")
def api_reports(
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> list[dict[str, Any]]:
    enforce_rate_limit(request, "reports_list", limit=60, window_sec=60)
    report_service.cleanup_retention(int(get_settings().get("retention_minutes") or 0))
    return report_service.list_reports()


@app.post("/api/analyze-pcap")
async def api_analyze_pcap(
    file: UploadFile = File(...),
    request: Request = None,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    enforce_rate_limit(request, "analyze_pcap", limit=8, window_sec=60)
    audit_event(
        "analyze_pcap_requested",
        actor=_actor_from_request(request),
        detail={
            "filename": file.filename or "capture.pcap",
            "capture_mode": current_capture_policy().mode,
        },
    )
    import tempfile

    suffix = (Path(file.filename or "capture.pcap").suffix or ".pcap").lower()
    if suffix not in ALLOWED_PCAP_SUFFIXES:
        raise HTTPException(status_code=400, detail="Unsupported PCAP file type")
    try:
        total_bytes = 0
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            temp_path = tmp.name
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > MAX_PCAP_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413, detail="PCAP file is too large"
                    )
                tmp.write(chunk)
        try:
            return _load_pcap_analyzer()(temp_path)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        await file.close()
        temp_path_value = locals().get("temp_path")
        if temp_path_value:
            Path(temp_path_value).unlink(missing_ok=True)


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket) -> None:
    client_host = websocket.client.host if websocket.client else ""
    if not is_allowed_websocket_origin(websocket.headers.get("origin")):
        await websocket.close(code=1008)
        return
    try:
        token, accepted_protocol = extract_websocket_token(
            websocket.headers.get("sec-websocket-protocol"),
            websocket.query_params.get("token", ""),
        )
    except HTTPException:
        await websocket.close(code=1008)
        return
    if not is_trusted_websocket_client(client_host, token):
        await websocket.close(code=1008)
        return
    if client_host and client_host not in {"127.0.0.1", "::1", "localhost"}:
        audit_event(
            "remote_login_success",
            actor=client_host,
            detail={"path": "/ws/events", "transport": "websocket"},
        )
    await websocket.accept(subprotocol=accepted_protocol)
    queue = event_bus.subscribe()
    try:
        await websocket.send_json(
            {
                "version": 1,
                "type": "hello",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": {
                    **sniffer_service.get_state(),
                    "observability": _observability_snapshot(),
                },
            }
        )
        while True:
            message = await queue.get()
            started = time.perf_counter()
            try:
                await websocket.send_json(message)
                event_bus.record_send_latency(started, ok=True)
            except Exception:
                event_bus.record_send_latency(started, ok=False)
                raise
    except WebSocketDisconnect:
        pass
    finally:
        event_bus.unsubscribe(queue)
