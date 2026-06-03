from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
import time
from typing import Any

from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.schemas import AlertInvestigationContext, DashboardResponse, PacketFlowContext, PacketItem, AlertItem, PaginatedAlertsResponse, PaginatedPacketsResponse, SettingsPayload, StatusResponse
from backend.app.security import (
    allowed_origins,
    ensure_within_directory,
    enforce_rate_limit,
    extract_websocket_token,
    is_allowed_websocket_origin,
    is_local_token_enabled,
    is_trusted_websocket_client,
    require_local_token,
    require_server_safe_use_policy,
    require_trusted_client,
    validate_block_ip,
    validate_ip,
    validate_report_download_path,
)
from backend.app.services.event_bus import EventBus
from backend.app.services.audit_service import audit_event
from backend.app.services.export_service import ExportService
from backend.app.services.history_service import HistoryRepositoryError, HistoryService
from backend.app.services.investigation_export_service import InvestigationExportService
from backend.app.services.report_service import ReportService
from backend.app.services.settings_service import get_settings, update_settings
from backend.app.services.sniffer_service import CaptureStartUnavailableError, SnifferService
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
logger = logging.getLogger("netbotpro.api")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
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
        raise HTTPException(status_code=503, detail="Offline PCAP analysis is unavailable in this runtime") from exc
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
        logger.exception("request_failed method=%s path=%s", request.method, request.url.path)
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
    return update_settings(payload)


@app.post("/api/sniffer/start")
def api_start_sniffer(
    payload: dict[str, Any] | None = None,
    request: Request = None,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
    ___: None = Depends(require_server_safe_use_policy),
) -> dict[str, Any]:
    enforce_rate_limit(request, "sniffer_start", limit=12, window_sec=60)
    payload = payload or {}
    iface = payload.get("iface")
    try:
        state = sniffer_service.start(iface=iface)
        audit_event("capture_start", actor=_actor_from_request(request), detail={"iface": state.get("iface")})
        return state
    except CaptureStartUnavailableError as exc:
        logger.warning("capture_start_unavailable detail=%s", exc.detail)
        audit_event("capture_start", actor=_actor_from_request(request), success=False, detail={"detail": exc.detail, "iface": iface})
        raise HTTPException(status_code=409, detail=exc.detail) from exc


@app.post("/api/sniffer/stop")
def api_stop_sniffer(
    request: Request,
    _: None = Depends(require_trusted_client),
    __: None = Depends(require_local_token),
) -> dict[str, Any]:
    enforce_rate_limit(request, "sniffer_stop", limit=20, window_sec=60)
    state = sniffer_service.stop()
    audit_event("capture_stop", actor=_actor_from_request(request), detail={"iface": state.get("iface")})
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
        audit_event("export_create", actor=_actor_from_request(request), detail={"kind": result.get("format"), "path": result.get("path")})
        return result
    except ValueError as exc:
        audit_event("export_create", actor=_actor_from_request(request), success=False, detail={"detail": str(exc)})
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
        audit_event("export_create", actor=_actor_from_request(request), detail={"kind": result.get("kind"), "path": result.get("path")})
        return result
    except ValueError as exc:
        audit_event("export_create", actor=_actor_from_request(request), success=False, detail={"detail": str(exc)})
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
        audit_event("report_download", actor=_actor_from_request(request), success=False, detail={"path": safe_name})
        raise HTTPException(status_code=404, detail="Export not found")
    audit_event("report_download", actor=_actor_from_request(request), detail={"path": safe_name})
    return FileResponse(file_path, filename=file_path.name, headers={"Cache-Control": "no-store"})


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
                    raise HTTPException(status_code=413, detail="PCAP file is too large")
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
        audit_event("remote_login", actor=client_host, detail={"path": "/ws/events", "transport": "websocket"})
    await websocket.accept(subprotocol=accepted_protocol)
    queue = event_bus.subscribe()
    try:
        await websocket.send_json(
            {
                "version": 1,
                "type": "hello",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": {**sniffer_service.get_state(), "observability": _observability_snapshot()},
            }
        )
        while True:
            message = await queue.get()
            await websocket.send_json(message)
    except WebSocketDisconnect:
        pass
    finally:
        event_bus.unsubscribe(queue)
