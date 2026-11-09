from __future__ import annotations

import logging
import os
import queue
import threading
import time
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.services.capture_policy import current_payload_capture_settings
from backend.app.services.event_bus import EventBus
from backend.app.services.flow_service import FlowService
from backend.app.services.flow_worker_pool import FlowWorkerPool
from backend.app.services.flow_view_batcher import FlowViewBatcher
from backend.app.services.stage_profiler import StageProfiler
from backend.app.services.incident_correlation import (
    IncidentCorrelationEngine,
    incident_markdown_summary,
)
from backend.app.services.live_ring_buffer import LiveRingBuffer
from backend.app.services.packet_queue import BoundedPacketQueue
from backend.app.services.redaction import redact_sensitive_data
from core.privacy_redaction import redaction_backend
from backend.app.services.service_attribution import ServiceAttributionEngine
from backend.app.services.settings_service import get_settings_snapshot
from backend.app.services.sniffer_dashboard_state import SnifferDashboardState
from backend.app.services.sniffer_detection_pipeline import SnifferDetectionPipeline
from backend.app.services.endpoint_risk_stats import EndpointRiskStats
from backend.app.services.sniffer_event_publisher import SnifferEventPublisher
from backend.app.services.sniffer_persistence import SnifferPersistence
from core.capture import CaptureProvider, CaptureSession, SystemCaptureProvider
from core.capture.process_session import ProcessCaptureSession
from core.expert_info import packet_expert_items
from core.flow_engine import flow_id_for

ensure_project_root_on_path()

logger = logging.getLogger(__name__)
CAPTURE_START_TIMEOUT_SEC = float(
    os.environ.get("NETBOT_CAPTURE_START_TIMEOUT_SEC", "15.0")
)
PACKET_QUEUE_MAX_SIZE = int(os.environ.get("NETBOT_PACKET_QUEUE_MAX_SIZE", "8192"))
PACKET_QUEUE_OVERFLOW_POLICY = os.environ.get(
    "NETBOT_PACKET_QUEUE_OVERFLOW_POLICY",
    "drop_oldest",
)
PACKET_QUEUE_DRAIN_TIMEOUT_SEC = float(
    os.environ.get("NETBOT_PACKET_QUEUE_DRAIN_TIMEOUT_SEC", "5.0")
)
REPEATED_ALERT_TYPES = frozenset({"Generic Flood / High Rate", "ML Anomaly / Robot Detection"})
REPEATED_ALERT_INTERVAL_SEC = 30.0


class SessionResetUnavailableError(RuntimeError):
    pass


class CaptureStopUnavailableError(RuntimeError):
    pass


class CaptureStartUnavailableError(RuntimeError):
    def __init__(self, detail: str, *, preflight: dict[str, Any] | None = None) -> None:
        super().__init__(detail)
        self.detail = detail
        self.preflight = preflight or {}


class SnifferService:
    def __init__(
        self,
        event_bus: EventBus,
        capture_provider: CaptureProvider | None = None,
        flow_service: FlowService | None = None,
        live_ring_buffer: LiveRingBuffer | None = None,
        service_attribution: ServiceAttributionEngine | None = None,
        incident_correlation: IncidentCorrelationEngine | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._event_bus = event_bus
        self._lifecycle_lock = threading.RLock()
        self._capture_provider = capture_provider or SystemCaptureProvider()
        self._engine: CaptureSession | None = None
        self._final_capture_status = None
        self._exit_prepared = False
        self._iface: str | None = None
        self._packet_seq = 0
        self._alert_seq = 0
        self._alert_coalesce_lock = threading.Lock()
        self._recent_alerts: OrderedDict[tuple[str, ...], tuple[float, int, int]] = OrderedDict()
        self._alerts_coalesced = 0
        self._state = SnifferDashboardState()
        self._endpoint_risk = EndpointRiskStats()
        self._detection_pipeline = SnifferDetectionPipeline(
            settings_provider=get_settings_snapshot
        )
        self._flow_service = flow_service or FlowService(persistent_writer=True)
        flow_writer = getattr(self._flow_service, "write_snapshots", None)
        self._deferred_flow_snapshots = callable(getattr(self._flow_service, "ingest_live", None)) and callable(getattr(self._flow_service, "write_live_snapshots", None))
        if self._deferred_flow_snapshots:
            flow_writer = self._flow_service.write_live_snapshots
        self._central_flow_persistence = callable(flow_writer)
        self._persistence = SnifferPersistence(
            flow_writer=flow_writer if callable(flow_writer) else None
        )
        self._publisher = SnifferEventPublisher(event_bus)
        self._live_ring_buffer = live_ring_buffer or LiveRingBuffer.from_env()
        self._flow_views = FlowViewBatcher(self._record_flow_view) if type(self._flow_service) is FlowService else None
        self._service_attribution = (
            service_attribution or ServiceAttributionEngine.from_env()
        )
        self._incident_correlation = (
            incident_correlation or IncidentCorrelationEngine.from_env()
        )
        self._packet_queue = BoundedPacketQueue(
            max_size=PACKET_QUEUE_MAX_SIZE,
            overflow_policy=PACKET_QUEUE_OVERFLOW_POLICY,
        )
        self._stage_profiler = None
        if os.environ.get('NETBOT_PROFILE_STAGES', '') == '1':
            self._stage_profiler = StageProfiler()
            for owner, method, label in (
                (self, '_process_packet', 'total_packet'),
                (self._detection_pipeline, 'analyze', 'detection'),
                (self._service_attribution, 'enrich', 'attribution'),
                (self._flow_service, 'ingest_for_analysis', 'flow'),
                (self._incident_correlation, 'correlate', 'correlation'),
                (self._live_ring_buffer, 'append', 'ring_append'),
                (self._publisher, 'publish_packet', 'packet_publication'),
                (self._persistence, 'persist_flow', 'persistence_enqueue'),
            ):
                if callable(getattr(owner, method, None)):
                    self._stage_profiler.wrap(owner, method, label)
        self._flow_worker_pool = (FlowWorkerPool(self._process_packet, enabled=False)
                                  if os.environ.get('NETBOT_CAPTURE_JOURNAL', '') == '1'
                                  else FlowWorkerPool.from_env(self._process_packet))
        self._packet_worker_stop = threading.Event()
        self._packet_worker = threading.Thread(
            target=self._packet_worker_loop,
            name="netbotpro-packet-queue",
            daemon=True,
        )
        self._packet_worker.start()
        self._stability_recorder = None
        if os.environ.get('NETBOT_STABILITY_RECORDING', '') == '1':
            from backend.app.services.stability_recorder import StabilityRecorder
            from log_manager import LOG_DIR
            self._stability_recorder = StabilityRecorder(self.observability, LOG_DIR / 'stability.jsonl')
            self._stability_recorder.start()

    @staticmethod
    def _first_blocking_preflight_detail(preflight: dict[str, Any]) -> str:
        for check in preflight.get("checks", []):
            if not check.get("ok") and str(check.get("severity") or "error") == "error":
                detail = str(check.get("detail") or "").strip()
                if detail:
                    return detail
        return "Live capture is unavailable in the current runtime."

    def _start_capture_session(self, iface: str | None) -> tuple[CaptureSession, str]:
        preflight = self.capture_preflight()
        if not preflight.get("ready"):
            raise CaptureStartUnavailableError(
                self._first_blocking_preflight_detail(preflight), preflight=preflight
            )
        iface = self._resolve_local_interface_or_raise(iface)

        result: dict[str, Any] = {}
        error: dict[str, BaseException] = {}

        def runner() -> None:
            try:
                engine = self._capture_provider.create_session(self._on_packet)
                if isinstance(engine, ProcessCaptureSession):
                    engine.set_batch_preparer(self._detection_pipeline.prepare_batch)
                engine.start(iface=iface)
                actual_iface = engine.selected_iface() or iface or "default"
                result["engine"] = engine
                result["iface"] = self._capture_provider.describe_interface(
                    actual_iface
                ) or str(actual_iface)
            except BaseException as exc:  # pragma: no cover - defensive path
                error["exc"] = exc

        worker = threading.Thread(
            target=runner, name="netbotpro-capture-start", daemon=True
        )
        worker.start()
        worker.join(CAPTURE_START_TIMEOUT_SEC)

        if worker.is_alive():
            raise CaptureStartUnavailableError(
                "Live capture startup timed out. Check Npcap/adapter readiness and run the desktop app as Administrator.",
                preflight=preflight,
            )
        if "exc" in error:
            raise CaptureStartUnavailableError(
                f"Live capture failed to start: {error['exc'].__class__.__name__}",
                preflight=preflight,
            ) from error["exc"]
        return result["engine"], result["iface"]

    def _resolve_local_interface_or_raise(self, iface: str | None) -> str | None:
        candidate = str(iface or "").strip()
        if not candidate or candidate in {"iface=default", "default"}:
            return None
        interfaces = self._capture_provider.list_interfaces()
        aliases: set[str] = set()
        values: set[str] = set()
        for item in interfaces.get("items", []):
            value = str(item.get("value") or "").strip()
            if value:
                values.add(value)
            for key in ("value", "name", "network_name", "label"):
                alias = str(item.get(key) or "").strip()
                if alias:
                    aliases.add(alias)
        if candidate not in aliases:
            raise CaptureStartUnavailableError(
                "Capture interface must be one of the local interfaces reported by this server.",
                preflight=self.capture_preflight(),
            )
        resolved = self._capture_provider.resolve_interface(candidate)
        if resolved and resolved in values:
            return resolved
        if candidate in values:
            return candidate
        raise CaptureStartUnavailableError(
            "Capture interface could not be resolved to a local server adapter.",
            preflight=self.capture_preflight(),
        )

    def _on_packet(self, meta: dict[str, Any]) -> None:
        if os.environ.get('NETBOT_CAPTURE_JOURNAL', '') == '1':
            self._process_packet(meta)
            return
        accepted = self._packet_queue.put(meta)
        if not accepted:
            logger.warning("packet intake queue full; dropped newest packet")

    def _process_packet(self, meta: dict[str, Any]) -> None:
        packet = dict(meta)
        packet.setdefault("ts", datetime.now(timezone.utc).isoformat())
        packet.setdefault("id", self._next_packet_id())
        payload_settings = current_payload_capture_settings()
        self._apply_payload_policy(packet, payload_settings)
        journal_mode = os.environ.get('NETBOT_CAPTURE_JOURNAL', '') == '1'
        prior_errors = self._detection_pipeline.error_count() if journal_mode else 0
        try:
            alerts = self._detection_pipeline.analyze(packet)
        except Exception:
            logger.exception("Packet analysis pipeline crashed")
            if journal_mode:
                raise
            alerts = []
        if journal_mode and self._detection_pipeline.error_count() != prior_errors:
            raise RuntimeError('Detector failed; journal batch must be retained')
        alerts = self._coalesce_repeated_alerts(packet, alerts)
        self._service_attribution.enrich(packet)
        alerts = self._assign_alert_ids(packet, alerts)
        self._endpoint_risk.observe(alerts)
        for alert in alerts:
            self._apply_payload_policy(alert, payload_settings)

        if self._deferred_flow_snapshots:
            flow = (self._flow_service.ingest_for_analysis(packet, alerts)
                    if type(self._flow_service) is FlowService
                    else self._flow_service.ingest_live(packet, alerts))
        elif self._central_flow_persistence:
            flow = self._flow_service.ingest(packet, alerts, persist=False)
        else:
            flow = self._flow_service.ingest(packet, alerts)
        flow_key = str((flow or {}).get("flow_id") or flow_id_for(packet))
        try:
            expert_items = packet_expert_items(packet, flow_key)
        except Exception as exc:  # pragma: no cover - defensive hot-path guard
            logger.warning(
                "live ring expert generation failed error_type=%s",
                type(exc).__name__,
            )
            expert_items = []
        incidents = self._incident_correlation.correlate(
            packet=packet,
            flow=flow,
            alerts=alerts,
            expert_items=expert_items,
            compact=True,
        )
        self._state.add_packet(packet)
        self._state.add_alerts(alerts)
        self._live_ring_buffer.append(
            "packet",
            packet,
            flow_key=flow_key,
            timestamp=str(packet.get("ts") or packet.get("timestamp") or ""),
            source="live_capture",
            return_record=False,
        )
        if isinstance(flow, dict):
            live_flow = dict(flow)
            for field in ("timeline", "related_alert_ids"):
                values = flow.get(field) or []
                live_flow[field] = values[-20:]
                live_flow[f"{field}_total"] = flow.get(f"{field}_total", len(values))
                live_flow[f"{field}_truncated"] = flow.get(f"{field}_truncated", len(values) > 20)
            if self._flow_views is not None:
                self._flow_views.submit(live_flow)
            else:
                self._record_flow_view(live_flow)
        for alert in alerts:
            self._live_ring_buffer.append(
                "alert",
                alert,
                flow_key=flow_key,
                timestamp=str(alert.get("ts") or alert.get("timestamp") or ""),
                source="detection_engine",
                return_record=False,
            )
        for expert_item in expert_items:
            self._live_ring_buffer.append(
                "expert_info",
                expert_item,
                flow_key=flow_key,
                timestamp=str(expert_item.get("last_seen") or ""),
                source="expert_info",
                return_record=False,
            )
        for incident in incidents:
            append_incident = (self._live_ring_buffer.append_redacted
                               if type(self._incident_correlation) is IncidentCorrelationEngine
                               else self._live_ring_buffer.append)
            append_incident(
                "incident",
                incident,
                flow_key=flow_key,
                timestamp=str(incident.get("last_seen") or ""),
                source="incident_correlation",
                return_record=False,
            )
        self._persistence.persist(packet, alerts)
        if self._central_flow_persistence and isinstance(flow, dict):
            self._persistence.persist_flow(
                {"flow_id": flow["flow_id"]} if self._deferred_flow_snapshots else flow
            )
        self._publisher.publish_packet(packet)
        self._publisher.publish_alerts(alerts)
        self._publisher.publish_incidents(incidents)

    def _packet_worker_loop(self) -> None:
        while not self._packet_worker_stop.is_set() or not self._packet_queue.empty():
            try:
                item = self._packet_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                if self._flow_worker_pool.enabled:
                    self._flow_worker_pool.submit(item.packet)
                else:
                    self._process_packet(item.packet)
            except Exception:
                logger.exception("Packet processing pipeline crashed")
            finally:
                self._packet_queue.task_done()

    def _record_flow_view(self, flow):
        append = self._live_ring_buffer.append
        append('flow', flow, flow_key=str(flow['flow_id']),
               timestamp=str(flow.get('last_seen') or ''),
               source='flow_view_batch', return_record=False)

    def drain_packet_queue(
        self, timeout_sec: float = PACKET_QUEUE_DRAIN_TIMEOUT_SEC
    ) -> bool:
        started = datetime.now().timestamp()
        intake_drained = self._packet_queue.wait_until_drained(timeout_sec)
        remaining = max(0.0, timeout_sec - (datetime.now().timestamp() - started))
        workers_drained = self._flow_worker_pool.wait_until_drained(remaining)
        if intake_drained and workers_drained and self._flow_views is not None:
            self._flow_views.flush()
        return intake_drained and workers_drained

    @staticmethod
    def _apply_payload_policy(row: dict[str, Any], settings: dict[str, Any]) -> None:
        if (
            bool(settings.get("payload_capture_enabled"))
            and not bool(settings.get("alert_only_mode"))
            and settings.get("capture_mode") in {"full", "forensic"}
        ):
            return
        row["payload_hex"] = ""
        row["payload_ascii"] = ""

    def start(self, iface: str | None = None) -> dict[str, Any]:
        with self._lifecycle_lock:
            return self._start_session(iface)

    def _start_session(self, iface: str | None = None) -> dict[str, Any]:
        if self._exit_prepared:
            raise CaptureStartUnavailableError("Runtime is prepared to exit; restart the application")
        if self._engine is not None and not self._capture_runtime_state()["running"]:
            self.stop()
        if self._engine is None:
            self.drain_packet_queue()
            self.reset_session()
        with self._lock:
            if self._engine is not None:
                already_running = True
            else:
                already_running = False
                self._engine, self._iface = self._start_capture_session(iface)
                self._final_capture_status = None
        if already_running:
            return self.get_state()
        state = self.get_state()
        self._publisher.publish_state("sniffer:started", state)
        return state

    def stop(self) -> dict[str, Any]:
        with self._lifecycle_lock:
            return self._stop_session()

    def prepare_exit(self) -> dict[str, Any]:
        with self._lifecycle_lock:
            state = self._stop_session()
            if state.get("running") is not False:
                raise CaptureStopUnavailableError("Capture has not stopped; retry exit")
            if not self._persistence.flush():
                raise CaptureStopUnavailableError("History is still draining; retry exit")
            self._exit_prepared = True
            return {**state, "exit_prepared": True}

    def _stop_session(self) -> dict[str, Any]:
        with self._lock:
            engine = self._engine
        if engine is not None:
            try:
                engine.stop()
            except Exception as exc:
                if not isinstance(engine, ProcessCaptureSession) or not engine.shutdown_ready():
                    raise CaptureStopUnavailableError('Capture driver did not stop; retry stop before resetting') from exc
                logger.warning('Capture failed but its process and accepted metadata have drained')
            status_reader = getattr(engine, 'capture_status', None)
            final_status = status_reader() if callable(status_reader) else None
            with self._lock:
                if self._engine is engine:
                    self._final_capture_status = deepcopy(final_status) if isinstance(final_status, dict) else None
                    self._engine = None
        if not self.drain_packet_queue():
            raise CaptureStopUnavailableError('Capture stopped but packet analysis is still draining; retry stop')
        state = self.get_state()
        self._publisher.publish_state("sniffer:stopped", state)
        return state

    def close(self) -> None:
        if self._stability_recorder is not None:
            self._stability_recorder.close()
        self.stop()
        self.drain_packet_queue()
        self._packet_worker_stop.set()
        if self._packet_worker.is_alive():
            self._packet_worker.join(timeout=1.0)
        self._flow_worker_pool.close()
        if self._flow_views is not None:
            self._flow_views.close()
        self._persistence.close()
        close_flow_service = getattr(self._flow_service, "close", None)
        if callable(close_flow_service):
            close_flow_service()

    def get_state(self) -> dict[str, Any]:
        with self._lock:
            running = self._engine is not None
            iface = self._iface
        state = self._state.state(running=running, iface=iface)
        capture_state = self._capture_runtime_state()
        state.update(capture_state)
        state["observability"] = self.observability(capture_state=capture_state)
        state["capture_health"] = state.get("health", "idle")
        statuses = [item.get("health") for item in state["observability"].values() if isinstance(item, dict)]
        if "critical" in statuses:
            state["health"] = "critical"
        elif "degraded" in statuses:
            state["health"] = "degraded"
        return state

    def _capture_runtime_state(self) -> dict[str, Any]:
        with self._lock:
            engine = self._engine
            final_status = getattr(self, '_final_capture_status', None)
        if engine is None and final_status is not None:
            return {**deepcopy(final_status), 'running': False}
        status = getattr(engine, "capture_status", None)
        if callable(status):
            result = status()
            selected = result.get("selected_iface")
            if selected:
                with self._lock:
                    previous = getattr(self, "_runtime_selected_iface", None)
                if selected != previous:
                    label = self._capture_provider.describe_interface(selected) or str(selected)
                    with self._lock:
                        self._runtime_selected_iface = selected
                        self._iface = label
                with self._lock:
                    result["iface"] = self._iface
            return result
        return {"running": engine is not None, "health": "healthy" if engine else "idle"}

    def recent_packets(self) -> list[dict[str, Any]]:
        if self._live_ring_buffer.enabled:
            return self._live_ring_buffer.recent_payloads("packet")
        return self._state.recent_packets()

    def recent_packet_refs(self) -> list[dict[str, Any]]:
        if self._live_ring_buffer.enabled:
            return self._live_ring_buffer.recent_payload_refs("packet")
        return self._state.recent_packets()

    def retained_record(self, category: str, record_id: str) -> dict[str, Any] | None:
        return self._live_ring_buffer.get_payload(category, record_id)

    def recent_alerts(self) -> list[dict[str, Any]]:
        if self._live_ring_buffer.enabled:
            return self._live_ring_buffer.recent_payloads("alert")
        return self._state.recent_alerts()

    def dashboard(self) -> dict[str, Any]:
        with self._lock:
            running = self._engine is not None
            iface = self._iface
        dashboard = self._state.dashboard(running=running, iface=iface)
        current = self.get_state()
        dashboard["state"].update(current)
        dashboard["observability"] = current["observability"]
        # Detach and sanitize the small read snapshot outside capture locks.
        return redact_sensitive_data(dashboard)

    def reset_session(self) -> dict[str, Any]:
        with self._lifecycle_lock:
            return self._reset_session()

    def _reset_session(self) -> dict[str, Any]:
        with self._lock:
            if self._engine is not None:
                raise SessionResetUnavailableError('Stop capture before resetting the session')
        if not self.drain_packet_queue():
            raise SessionResetUnavailableError('Pending packets must finish before resetting the session')
        if self._deferred_flow_snapshots and not self._persistence.flush():
            raise SessionResetUnavailableError("Pending flow snapshots must be saved before reset")
        self._state.reset()
        self._final_capture_status = None
        self._detection_pipeline.reset_signature_context()
        self._endpoint_risk.reset()
        self._flow_service.reset()
        if self._flow_views is not None:
            self._flow_views.clear()
        self._live_ring_buffer.clear()
        self._service_attribution.reset_runtime()
        self._incident_correlation.reset()
        with self._alert_coalesce_lock:
            self._recent_alerts.clear()
            self._alerts_coalesced = 0
        state = self.get_state()
        self._publisher.publish_state("sniffer:reset", state)
        return state

    def endpoint_risk_summary(self) -> dict[str, Any]:
        return self._endpoint_risk.snapshot()

    def persistence_stats(self) -> dict[str, Any]:
        stats = self._persistence.stats()
        stats["enabled"] = bool(stats.get("persistence_enabled", stats.get("enabled")))
        stats["packet_storage_enabled"] = bool(stats.get("packet_storage_enabled", False))
        stats["alert_storage_enabled"] = bool(stats.get("alert_storage_enabled", False))
        stats["flows"] = {
            **(self._flow_service.storage_metrics() if type(self._flow_service) is FlowService else {}),
            "enabled": bool(stats.get("flow_storage_enabled")),
            "worker_alive": bool(stats.get("worker_alive")),
        }
        return stats

    def packet_queue_stats(self) -> dict[str, Any]:
        return self._packet_queue.stats(worker_alive=self._packet_worker.is_alive())

    def flow_worker_pool_stats(self) -> dict[str, Any]:
        return self._flow_worker_pool.stats()

    def live_ring_buffer_stats(self) -> dict[str, Any]:
        return self._live_ring_buffer.metrics()

    def service_attribution_stats(self) -> dict[str, Any]:
        return self._service_attribution.metrics()

    def incident_correlation_stats(self) -> dict[str, Any]:
        return self._incident_correlation.metrics()

    def list_incidents(self, **filters: Any) -> dict[str, Any]:
        return self._incident_correlation.list_incidents(**filters)

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        return self._incident_correlation.get_incident(incident_id)

    def incident_summary_markdown(self, incident_id: str) -> str | None:
        incident = self.get_incident(incident_id)
        return incident_markdown_summary(incident) if incident else None

    def recent_live_records(
        self,
        category: str = "all",
        *,
        limit: int | None = None,
        flow_key: str = "",
        since: str | None = None,
    ) -> dict[str, Any]:
        return self._live_ring_buffer.query(
            category,
            limit=limit,
            flow_key=flow_key,
            since=since,
        )

    def auto_block_stats(self) -> dict[str, int | float]:
        stats = self._detection_pipeline.stats()
        with self._alert_coalesce_lock:
            stats["repeated_alerts_coalesced_total"] = self._alerts_coalesced
        return stats

    def _coalesce_repeated_alerts(
        self, packet: dict[str, Any], alerts: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        if not alerts:
            return alerts
        result = []
        now = time.monotonic()
        with self._alert_coalesce_lock:
            for alert in alerts:
                attack = str(alert.get("attack_type") or "")
                if attack not in REPEATED_ALERT_TYPES:
                    result.append(alert)
                    continue
                key = (
                    attack,
                    str(packet.get("src") or ""),
                    str(packet.get("dst") or "") if attack != "Generic Flood / High Rate" else "",
                    str(alert.get("severity") or ""),
                )
                last, emitted, pending = self._recent_alerts.get(key, (0.0, 0, 0))
                if emitted and now - last < REPEATED_ALERT_INTERVAL_SEC:
                    self._recent_alerts[key] = (last, emitted, pending + 1)
                    self._recent_alerts.move_to_end(key)
                    self._alerts_coalesced += 1
                    continue
                row = dict(alert)
                if pending:
                    row["coalesced_occurrences"] = pending + 1
                result.append(row)
                self._recent_alerts[key] = (now, emitted + 1, 0)
                self._recent_alerts.move_to_end(key)
            while len(self._recent_alerts) > 20_000:
                self._recent_alerts.popitem(last=False)
        return result

    def observability(self, *, capture_state: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "stage_profile": self._stage_profiler.stats() if self._stage_profiler is not None else {"enabled": False},
            "redaction": {"backend": redaction_backend()},
            "stability": self._stability_recorder.stats() if self._stability_recorder is not None else {"enabled": False},
            "analysis_delivery": {"mode": "journal_inline" if os.environ.get('NETBOT_CAPTURE_JOURNAL', '') == '1' else "worker_pool"},
            'flow_views': self._flow_views.stats() if self._flow_views is not None else {'enabled': False},
            'flow_memory': self._flow_service.memory_stats() if type(self._flow_service) is FlowService else {'enabled': False},
            "capture": self._capture_runtime_state() if capture_state is None else deepcopy(capture_state),
            "event_bus": self._event_bus.stats(),
            "packet_queue": self.packet_queue_stats(),
            "flow_worker_pool": self.flow_worker_pool_stats(),
            "live_ring_buffer": self.live_ring_buffer_stats(),
            "service_attribution": self.service_attribution_stats(),
            "incidents": self.incident_correlation_stats(),
            "persistence": self.persistence_stats(),
            "auto_block": self.auto_block_stats(),
            "alert_engine": self._detection_pipeline.health_stats(),
            "threat_intelligence": {"enabled": False, "health": "not configured", "reason": "No threat intelligence provider is configured"},
        }

    @property
    def flow_service(self) -> FlowService:
        return self._flow_service

    def capture_interfaces(self) -> dict[str, Any]:
        payload = self._capture_provider.list_interfaces()
        payload["preflight"] = self.capture_preflight()
        return payload

    def capture_preflight(self) -> dict[str, Any]:
        return self._capture_provider.preflight().to_dict()

    def _next_packet_id(self) -> str:
        with self._lock:
            self._packet_seq += 1
            return f"mem-pkt-{self._packet_seq}"

    def _assign_alert_ids(
        self, packet: dict[str, Any], alerts: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        if not alerts:
            return []
        normalized: list[dict[str, Any]] = []
        flow_id = flow_id_for(packet)
        for alert in alerts:
            row = dict(alert)
            with self._lock:
                self._alert_seq += 1
                row.setdefault("id", f"mem-alert-{self._alert_seq}")
            row.setdefault("packet_id", packet.get("id"))
            row.setdefault("flow_id", flow_id)
            normalized.append(row)
        return normalized
