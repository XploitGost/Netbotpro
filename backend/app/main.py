from __future__ import annotations

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
from fastapi.responses import FileResponse

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
from backend.app.services.agent_registry import AgentRegistry
from backend.app.services.audit_service import audit_event
from backend.app.services.capture_policy import (
    current_capture_policy,
    enforce_capture_policy,
)
from backend.app.services.event_bus import EventBus
from backend.app.services.export_service import ExportService
from backend.app.services.history_service import HistoryRepositoryError, HistoryService
from backend.app.services.investigation_export_service import InvestigationExportService
from backend.app.services.report_service import ReportService
from backend.app.services.settings_service import get_settings, update_settings
from backend.app.services.sniffer_service import (
    CaptureStartUnavailableError,
    SnifferService,
)
from backend.app.services.traceroute_service import TracerouteService
from core.capture import SystemCaptureProvider

ensure_project_root_on_path()

from core.firewall_tools import block_ip  # noqa: E402
from log_manager import LOG_DIR  # noqa: E402

event_bus = EventBus()
capture_provider = SystemCaptureProvider()
sniffer_service = SnifferService(event_bus, capture_provider=capture_provider)
traceroute_service = TracerouteService()
export_service = ExportService()
investigation_export_service = InvestigationExportService()
history_service = HistoryService(sniffer_service)
report_service = ReportService()
agent_registry = AgentRegistry()
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
        "history": history_service.metrics(),
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
    sniffer_service.close()


app = FastAPI(
    title="NetBotPro API",
    version="0.1.3",
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
    limit: int = 20,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    agent = agent_registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {
        "agent": agent,
        "items": agent_registry.get_telemetry(agent_id, limit=limit),
    }


@app.get("/api/settings", response_model=SettingsPayload)
def api_get_settings(
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    return get_settings()


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
    limit: int = 50,
    offset: int = 0,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    try:
        return await history_service.aget_packets(
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
    except HistoryRepositoryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


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
        return _load_pcap_analyzer()(temp_path)
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
            await websocket.send_json(message)
    except WebSocketDisconnect:
        pass
    finally:
        event_bus.unsubscribe(queue)
