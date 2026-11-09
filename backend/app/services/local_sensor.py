"""Lifecycle-managed, metadata-only telemetry for the desktop's own sensor."""
from __future__ import annotations

import hashlib
import logging
import platform
import socket
import threading

logger = logging.getLogger(__name__)


class LocalSensorReporter:
    def __init__(self, registry, sniffer, flows, *, interval=10.0, hostname=None):
        self.registry = registry
        self.sniffer = sniffer
        self.flows = flows
        self.interval = max(0.1, interval)
        self.hostname = hostname or socket.gethostname()
        self.agent_id = "desktop-local-" + hashlib.sha256(
            self.hostname.casefold().encode("utf-8")).hexdigest()[:20]
        self._stop = threading.Event()
        self._thread = None

    def publish(self):
        """Publish counters only, without packet contents or capture side effects."""
        state = self.sniffer.get_state()
        metrics = self.sniffer.observability()
        summary = self.flows.summary()
        self.registry.heartbeat(self.agent_id, {"status": "online"})
        self.registry.telemetry(self.agent_id, {
            "capture_status": {"running": bool(state.get("running")),
                "health": state.get("capture_health", "idle"),
                "packets": state.get("total_packets", 0)},
            "health": {"packet_queue": metrics.get("packet_queue", {}),
                "flow_worker_pool": metrics.get("flow_worker_pool", {}),
                "persistence": metrics.get("persistence", {})},
            "flows_summary": {key: summary.get(key) for key in
                ("total_flows", "bytes_total", "risk_distribution", "protocol_distribution")},
            "metadata_redacted": True,
        })

    def _run(self):
        registered = False
        while not self._stop.is_set():
            try:
                if not registered:
                    self.registry.register_local_sensor({"agent_id": self.agent_id,
                        "hostname": self.hostname, "display_name": self.hostname + " (Local)",
                        "os": platform.system(), "platform": platform.system(),
                        "agent_version": "0.2.0", "version": "0.2.0"})
                    registered = True
                self.publish()
            except Exception:
                logger.exception("local sensor telemetry failed")
            if self._stop.wait(self.interval):
                break
        if registered:
            try:
                self.registry.heartbeat(self.agent_id, {"status": "offline"})
            except Exception:
                logger.exception("local sensor shutdown heartbeat failed")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="desktop-local-sensor", daemon=True)
        self._thread.start()

    def close(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5.0)
