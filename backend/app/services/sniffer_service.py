from __future__ import annotations

import logging
import os
import queue
import threading
from datetime import datetime
from typing import Any

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.services.event_bus import EventBus
from backend.app.services.capture_policy import current_capture_policy
from backend.app.services.flow_service import FlowService
from backend.app.services.packet_queue import BoundedPacketQueue
from backend.app.services.settings_service import get_settings_snapshot
from backend.app.services.sniffer_dashboard_state import SnifferDashboardState
from backend.app.services.sniffer_detection_pipeline import SnifferDetectionPipeline
from backend.app.services.sniffer_event_publisher import SnifferEventPublisher
from backend.app.services.sniffer_persistence import SnifferPersistence
from core.capture import CaptureProvider, CaptureSession, SystemCaptureProvider

ensure_project_root_on_path()

logger = logging.getLogger(__name__)
CAPTURE_START_TIMEOUT_SEC = float(os.environ.get("NETBOT_CAPTURE_START_TIMEOUT_SEC", "15.0"))
PACKET_QUEUE_MAX_SIZE = int(os.environ.get("NETBOT_PACKET_QUEUE_MAX_SIZE", "2000"))
PACKET_QUEUE_OVERFLOW_POLICY = os.environ.get(
    "NETBOT_PACKET_QUEUE_OVERFLOW_POLICY",
    "drop_oldest",
)
PACKET_QUEUE_DRAIN_TIMEOUT_SEC = float(
    os.environ.get("NETBOT_PACKET_QUEUE_DRAIN_TIMEOUT_SEC", "5.0")
)


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
    ) -> None:
        self._lock = threading.Lock()
        self._event_bus = event_bus
        self._capture_provider = capture_provider or SystemCaptureProvider()
        self._engine: CaptureSession | None = None
        self._iface: str | None = None
        self._packet_seq = 0
        self._alert_seq = 0
        self._state = SnifferDashboardState()
        self._detection_pipeline = SnifferDetectionPipeline(settings_provider=get_settings_snapshot)
        self._persistence = SnifferPersistence()
        self._publisher = SnifferEventPublisher(event_bus)
        self._flow_service = flow_service or FlowService()
        self._packet_queue = BoundedPacketQueue(
            max_size=PACKET_QUEUE_MAX_SIZE,
            overflow_policy=PACKET_QUEUE_OVERFLOW_POLICY,
        )
        self._packet_worker_stop = threading.Event()
        self._packet_worker = threading.Thread(
            target=self._packet_worker_loop,
            name="netbotpro-packet-queue",
            daemon=True,
        )
        self._packet_worker.start()

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
            raise CaptureStartUnavailableError(self._first_blocking_preflight_detail(preflight), preflight=preflight)
        iface = self._resolve_local_interface_or_raise(iface)

        result: dict[str, Any] = {}
        error: dict[str, BaseException] = {}

        def runner() -> None:
            try:
                engine = self._capture_provider.create_session(self._on_packet)
                engine.start(iface=iface)
                actual_iface = engine.selected_iface() or iface or "default"
                result["engine"] = engine
                result["iface"] = self._capture_provider.describe_interface(actual_iface) or str(actual_iface)
            except BaseException as exc:  # pragma: no cover - defensive path
                error["exc"] = exc

        worker = threading.Thread(target=runner, name="netbotpro-capture-start", daemon=True)
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
        accepted = self._packet_queue.put(meta)
        if not accepted:
            logger.warning("packet intake queue full; dropped newest packet")

    def _process_packet(self, meta: dict[str, Any]) -> None:
        packet = dict(meta)
        packet.setdefault("ts", datetime.utcnow().isoformat() + "Z")
        packet.setdefault("id", self._next_packet_id())
        policy = current_capture_policy()
        self._apply_payload_policy(packet, policy.to_public_dict())
        try:
            alerts = self._detection_pipeline.analyze(packet)
        except Exception:
            logger.exception("Packet analysis pipeline crashed")
            alerts = []
        alerts = self._assign_alert_ids(packet, alerts)
        for alert in alerts:
            self._apply_payload_policy(alert, policy.to_public_dict())

        self._flow_service.ingest(packet, alerts)
        self._state.add_packet(packet)
        self._state.add_alerts(alerts)
        self._persistence.persist(packet, alerts)
        self._publisher.publish_packet(packet)
        self._publisher.publish_alerts(alerts)

    def _packet_worker_loop(self) -> None:
        while not self._packet_worker_stop.is_set() or not self._packet_queue.empty():
            try:
                item = self._packet_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                self._process_packet(item.packet)
            except Exception:
                logger.exception("Packet processing pipeline crashed")
            finally:
                self._packet_queue.task_done()

    def drain_packet_queue(self, timeout_sec: float = PACKET_QUEUE_DRAIN_TIMEOUT_SEC) -> bool:
        return self._packet_queue.wait_until_drained(timeout_sec)

    @staticmethod
    def _apply_payload_policy(row: dict[str, Any], settings: dict[str, Any]) -> None:
        if bool(settings.get("payload_capture_enabled")) and not bool(settings.get("alert_only_mode")) and settings.get("capture_mode") in {"full", "forensic"}:
            return
        row["payload_hex"] = ""
        row["payload_ascii"] = ""

    def start(self, iface: str | None = None) -> dict[str, Any]:
        with self._lock:
            if self._engine is not None:
                already_running = True
            else:
                already_running = False
                self._engine, self._iface = self._start_capture_session(iface)
        if already_running:
            return self.get_state()
        state = self.get_state()
        self._publisher.publish_state("sniffer:started", state)
        return state

    def stop(self) -> dict[str, Any]:
        with self._lock:
            engine = self._engine
            self._engine = None
        if engine is not None:
            engine.stop()
        state = self.get_state()
        self._publisher.publish_state("sniffer:stopped", state)
        return state

    def close(self) -> None:
        self.stop()
        self.drain_packet_queue()
        self._packet_worker_stop.set()
        if self._packet_worker.is_alive():
            self._packet_worker.join(timeout=1.0)
        self._persistence.close()

    def get_state(self) -> dict[str, Any]:
        with self._lock:
            running = self._engine is not None
            iface = self._iface
        state = self._state.state(running=running, iface=iface)
        state["observability"] = self.observability()
        return state

    def recent_packets(self) -> list[dict[str, Any]]:
        return self._state.recent_packets()

    def recent_alerts(self) -> list[dict[str, Any]]:
        return self._state.recent_alerts()

    def dashboard(self) -> dict[str, Any]:
        with self._lock:
            running = self._engine is not None
            iface = self._iface
        dashboard = self._state.dashboard(running=running, iface=iface)
        dashboard["observability"] = self.observability()
        return dashboard

    def reset_session(self) -> dict[str, Any]:
        with self._lock:
            running = self._engine is not None
            iface = self._iface
        self._state.reset()
        self._flow_service.reset()
        state = self._state.state(running=running, iface=iface)
        state["observability"] = self.observability()
        self._publisher.publish_state("sniffer:reset", state)
        return state

    def persistence_stats(self) -> dict[str, int | float]:
        return self._persistence.stats()

    def packet_queue_stats(self) -> dict[str, int | float | str | bool]:
        return self._packet_queue.stats(worker_alive=self._packet_worker.is_alive())

    def auto_block_stats(self) -> dict[str, int | float]:
        return self._detection_pipeline.stats()

    def observability(self) -> dict[str, Any]:
        return {
            "event_bus": self._event_bus.stats(),
            "packet_queue": self.packet_queue_stats(),
            "persistence": self.persistence_stats(),
            "auto_block": self.auto_block_stats(),
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

    def _assign_alert_ids(self, packet: dict[str, Any], alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for alert in alerts:
            row = dict(alert)
            with self._lock:
                self._alert_seq += 1
                row.setdefault("id", f"mem-alert-{self._alert_seq}")
            row.setdefault("packet_id", packet.get("id"))
            normalized.append(row)
        return normalized
