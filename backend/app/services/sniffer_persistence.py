from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any

from backend.app.bootstrap import ensure_project_root_on_path

ensure_project_root_on_path()

from log_manager import insert_batch, is_persist_enabled  # noqa: E402

logger = logging.getLogger(__name__)


class SnifferPersistence:
    def __init__(
        self,
        batch_size: int = 100,
        flush_interval: float = 0.5,
        max_queue_size: int = 5000,
        max_batch_size: int | None = None,
        overload_policy: str = "drop_oldest",
    ) -> None:
        self._batch_size = max(1, int(batch_size))
        self._max_batch_size = max(self._batch_size, int(max_batch_size or max(self._batch_size * 4, 400)))
        self._flush_interval = max(0.1, float(flush_interval))
        self._queue: queue.Queue[tuple[dict[str, Any], list[dict[str, Any]]]] = queue.Queue(maxsize=max_queue_size)
        self._overload_policy = overload_policy if overload_policy in {"drop_oldest", "drop_newest"} else "drop_oldest"
        self._stop_event = threading.Event()
        self._worker = threading.Thread(target=self._worker_loop, daemon=True, name="SnifferPersistenceWorker")
        self._lock = threading.Lock()
        self._dropped_writes = 0
        self._persisted_packets = 0
        self._persisted_alerts = 0
        self._flush_batches = 0
        self._last_flush_ms = 0.0
        self._avg_flush_ms = 0.0
        self._avg_batch_size = 0.0
        self._flush_errors = 0
        self._flush_retries = 0
        self._queue_high_water_mark = 0
        self._last_batch_size = 0
        self._last_queue_drift_ms = 0.0
        self._drain_completed = 0
        self._shutdown_flush_timeout = 0
        self._worker.start()

    def persist(self, packet: dict[str, Any], alerts: list[dict[str, Any]]) -> None:
        if not is_persist_enabled():
            return

        packet_row = {
            "capture_id": packet.get("id"),
            "ts": packet.get("ts"),
            "src": packet.get("src"),
            "dst": packet.get("dst"),
            "proto": packet.get("proto"),
            "sport": packet.get("sport"),
            "dport": packet.get("dport"),
            "length": packet.get("length"),
            "country": packet.get("country") or packet.get("country_code"),
            "org": packet.get("org"),
            "summary": packet.get("summary"),
            "is_alert": bool(alerts),
            "remote_ip": packet.get("remote_ip"),
            "app_protocol": packet.get("app_protocol"),
            "app_category": packet.get("app_category"),
            "app_confidence": packet.get("app_confidence"),
            "protocol_basis": packet.get("protocol_basis"),
            "protocol_notes": packet.get("protocol_notes"),
            "protocol_handshake": packet.get("protocol_handshake"),
            "protocol_unusual_port": packet.get("protocol_unusual_port"),
            "l7": packet.get("l7"),
            "dns_qname": packet.get("dns_qname"),
            "dns_qtype": packet.get("dns_qtype"),
            "dns_rcode": packet.get("dns_rcode"),
            "http_method": packet.get("http_method"),
            "http_status": packet.get("http_status"),
            "http_reason": packet.get("http_reason"),
            "http_host": packet.get("http_host"),
            "http_path": packet.get("http_path"),
            "http_user_agent": packet.get("http_user_agent"),
            "http_content_type": packet.get("http_content_type"),
            "sni": packet.get("tls_sni") or packet.get("sni"),
            "tls_version": packet.get("tls_version"),
            "tls_alpn": packet.get("tls_alpn") or packet.get("alpn"),
            "ja3": packet.get("ja3"),
            "ja3_str": packet.get("ja3_str"),
            "ja4": packet.get("ja4"),
            "payload_len": packet.get("payload_len"),
            "payload_hex": packet.get("payload_hex"),
            "payload_ascii": packet.get("payload_ascii"),
            "payload_binary_like": packet.get("payload_binary_like"),
            "payload_entropy": packet.get("payload_entropy"),
            "payload_printable_ratio": packet.get("payload_printable_ratio"),
            "pid": packet.get("pid"),
            "process_name": packet.get("process_name"),
            "parent_pid": packet.get("parent_pid"),
            "parent_process_name": packet.get("parent_process_name"),
            "executable_path": packet.get("executable_path"),
            "attribution_confidence": packet.get("attribution_confidence"),
            "attribution_reason_unavailable": packet.get("attribution_reason_unavailable"),
            "attribution_source": packet.get("attribution_source"),
        }
        alert_rows = [
            {
                "ts": alert.get("ts"),
                "src": alert.get("src"),
                "dst": alert.get("dst"),
                "proto": alert.get("proto"),
                "sport": alert.get("sport") or packet.get("sport"),
                "dport": alert.get("dport") or packet.get("dport"),
                "direction": alert.get("direction") or packet.get("direction"),
                "attack_type": alert.get("attack_type"),
                "score": alert.get("score"),
                "detail": alert.get("detail"),
                "severity": alert.get("severity"),
                "engine": alert.get("engine"),
                "score_raw": alert.get("score_raw"),
                "incident_id": alert.get("incident_id"),
                "incident_count": alert.get("incident_count"),
                "incident_score": alert.get("incident_score"),
                "packet_id": alert.get("packet_id"),
                "remote_ip": alert.get("remote_ip") or packet.get("remote_ip"),
                "app_protocol": alert.get("app_protocol") or packet.get("app_protocol"),
                "app_category": alert.get("app_category") or packet.get("app_category"),
                "app_confidence": alert.get("app_confidence") or packet.get("app_confidence"),
                "protocol_basis": alert.get("protocol_basis") or packet.get("protocol_basis"),
                "protocol_notes": alert.get("protocol_notes") or packet.get("protocol_notes"),
                "protocol_handshake": alert.get("protocol_handshake") or packet.get("protocol_handshake"),
                "protocol_unusual_port": alert.get("protocol_unusual_port")
                if alert.get("protocol_unusual_port") is not None
                else packet.get("protocol_unusual_port"),
                "dns_qname": alert.get("dns_qname") or packet.get("dns_qname"),
                "dns_qtype": alert.get("dns_qtype") if alert.get("dns_qtype") is not None else packet.get("dns_qtype"),
                "dns_rcode": alert.get("dns_rcode") if alert.get("dns_rcode") is not None else packet.get("dns_rcode"),
                "http_method": alert.get("http_method") or packet.get("http_method"),
                "http_host": alert.get("http_host") or packet.get("http_host"),
                "http_path": alert.get("http_path") or packet.get("http_path"),
                "http_status": alert.get("http_status") if alert.get("http_status") is not None else packet.get("http_status"),
                "http_reason": alert.get("http_reason") or packet.get("http_reason"),
                "http_user_agent": alert.get("http_user_agent") or packet.get("http_user_agent"),
                "http_content_type": alert.get("http_content_type") or packet.get("http_content_type"),
                "sni": alert.get("sni") or packet.get("tls_sni") or packet.get("sni"),
                "tls_version": alert.get("tls_version") or packet.get("tls_version"),
                "tls_alpn": alert.get("tls_alpn") or packet.get("tls_alpn") or packet.get("alpn"),
                "ja3": alert.get("ja3") or packet.get("ja3"),
                "ja3_str": alert.get("ja3_str") or packet.get("ja3_str"),
                "ja4": alert.get("ja4") or packet.get("ja4"),
                "payload_len": alert.get("payload_len") if alert.get("payload_len") is not None else packet.get("payload_len"),
                "payload_hex": alert.get("payload_hex") or packet.get("payload_hex"),
                "payload_ascii": alert.get("payload_ascii") or packet.get("payload_ascii"),
                "payload_binary_like": alert.get("payload_binary_like")
                if alert.get("payload_binary_like") is not None
                else packet.get("payload_binary_like"),
                "payload_entropy": alert.get("payload_entropy") if alert.get("payload_entropy") is not None else packet.get("payload_entropy"),
                "payload_printable_ratio": alert.get("payload_printable_ratio")
                if alert.get("payload_printable_ratio") is not None
                else packet.get("payload_printable_ratio"),
                "pid": alert.get("pid") or packet.get("pid"),
                "process_name": alert.get("process_name") or packet.get("process_name"),
                "parent_pid": alert.get("parent_pid") or packet.get("parent_pid"),
                "parent_process_name": alert.get("parent_process_name") or packet.get("parent_process_name"),
                "executable_path": alert.get("executable_path") or packet.get("executable_path"),
                "attribution_confidence": alert.get("attribution_confidence") or packet.get("attribution_confidence"),
                "attribution_reason_unavailable": alert.get("attribution_reason_unavailable") or packet.get("attribution_reason_unavailable"),
                "attribution_source": alert.get("attribution_source") or packet.get("attribution_source"),
            }
            for alert in alerts
        ]

        try:
            self._queue.put_nowait((packet_row, alert_rows))
            with self._lock:
                self._queue_high_water_mark = max(self._queue_high_water_mark, self._queue.qsize())
        except queue.Full:
            if self._overload_policy == "drop_newest":
                with self._lock:
                    self._dropped_writes += 1
                    self._queue_high_water_mark = max(self._queue_high_water_mark, self._queue.qsize())
                logger.warning("persistence queue full; dropping newest packet row")
                return
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            with self._lock:
                self._dropped_writes += 1
            try:
                self._queue.put_nowait((packet_row, alert_rows))
                with self._lock:
                    self._queue_high_water_mark = max(self._queue_high_water_mark, self._queue.qsize())
            except queue.Full:
                with self._lock:
                    self._dropped_writes += 1
                logger.warning("persistence queue full; dropping packet row")

    def stats(self) -> dict[str, int | float]:
        with self._lock:
            return {
                "dropped_writes": self._dropped_writes,
                "persisted_packets": self._persisted_packets,
                "persisted_alerts": self._persisted_alerts,
                "queue_size": self._queue.qsize(),
                "flush_batches": self._flush_batches,
                "last_flush_ms": self._last_flush_ms,
                "avg_flush_ms": self._avg_flush_ms,
                "last_batch_size": self._last_batch_size,
                "avg_batch_size": self._avg_batch_size,
                "flush_errors": self._flush_errors,
                "flush_retries": self._flush_retries,
                "queue_high_water_mark": self._queue_high_water_mark,
                "last_queue_drift_ms": self._last_queue_drift_ms,
                "overload_policy": self._overload_policy,
                "drain_completed": self._drain_completed,
                "shutdown_flush_timeout": self._shutdown_flush_timeout,
            }

    def close(self, timeout_sec: float = 10.0) -> None:
        self._stop_event.set()
        if self._worker.is_alive():
            self._worker.join(timeout=max(2.0, timeout_sec))
        with self._lock:
            if self._worker.is_alive():
                self._shutdown_flush_timeout = 1
            elif self._queue.empty():
                self._drain_completed = 1

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                first_packet, first_alerts = self._queue.get(timeout=self._flush_interval)
            except queue.Empty:
                continue

            packet_rows = [first_packet]
            alert_rows = list(first_alerts)
            deadline = time.time() + self._flush_interval
            target_batch_size = self._target_batch_size()

            while len(packet_rows) < target_batch_size:
                try:
                    remaining = max(0.0, deadline - time.time())
                    if remaining == 0.0:
                        break
                    next_packet, next_alerts = self._queue.get(timeout=remaining)
                except queue.Empty:
                    break
                packet_rows.append(next_packet)
                alert_rows.extend(next_alerts)

            try:
                started = time.perf_counter()
                result = insert_batch(packet_rows, alert_rows)
                duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
                drift_ms = round(max(0.0, time.time() - deadline) * 1000.0, 2)
                retries = int(result.get("retries", 0)) if isinstance(result, dict) else 0
                with self._lock:
                    self._persisted_packets += len(packet_rows)
                    self._persisted_alerts += len(alert_rows)
                    self._flush_batches += 1
                    self._last_flush_ms = duration_ms
                    self._avg_flush_ms = round(((self._avg_flush_ms * (self._flush_batches - 1)) + duration_ms) / self._flush_batches, 2)
                    self._last_batch_size = len(packet_rows)
                    self._avg_batch_size = round(((self._avg_batch_size * (self._flush_batches - 1)) + len(packet_rows)) / self._flush_batches, 2)
                    self._flush_retries += retries
                    self._last_queue_drift_ms = drift_ms
            except Exception:
                with self._lock:
                    self._flush_errors += 1
                logger.exception("Failed to persist packet batch")

    def _target_batch_size(self) -> int:
        queue_size = self._queue.qsize()
        if queue_size <= 0:
            return self._batch_size
        adaptive_bonus = max(0, queue_size // 50)
        return min(self._max_batch_size, max(self._batch_size, self._batch_size + adaptive_bonus))
