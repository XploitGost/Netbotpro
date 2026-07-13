from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Callable

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.services.batch_persistence import BatchPersistenceWriter

ensure_project_root_on_path()

from log_manager import insert_batch  # noqa: E402
from log_manager import cleanup_retention, is_persist_enabled

logger = logging.getLogger(__name__)


class SnifferPersistence:
    def __init__(
        self,
        batch_size: int | None = None,
        flush_interval: float | None = None,
        max_queue_size: int | None = None,
        max_batch_size: int | None = None,
        overload_policy: str | None = None,
        max_retries: int | None = None,
        retry_backoff_sec: float | None = None,
        flow_writer: Callable[[list[dict[str, Any]]], None] | None = None,
    ) -> None:
        batch_size = batch_size or int(
            os.environ.get("NETBOT_PERSISTENCE_PACKET_BATCH_SIZE", "500")
        )
        flush_interval = flush_interval or (
            int(os.environ.get("NETBOT_PERSISTENCE_PACKET_FLUSH_MS", "1000")) / 1000.0
        )
        max_queue_size = max_queue_size or int(
            os.environ.get("NETBOT_PERSISTENCE_QUEUE_MAX", "5000")
        )
        overload_policy = overload_policy or os.environ.get(
            "NETBOT_PERSISTENCE_OVERFLOW_POLICY", "drop_oldest"
        )
        self._max_retries = max(
            0,
            int(
                max_retries
                if max_retries is not None
                else os.environ.get("NETBOT_PERSISTENCE_RETRY_MAX", "3")
            ),
        )
        self._retry_backoff_sec = max(
            0.0,
            float(
                retry_backoff_sec
                if retry_backoff_sec is not None
                else int(os.environ.get("NETBOT_PERSISTENCE_RETRY_BACKOFF_MS", "250"))
                / 1000.0
            ),
        )
        self._batch_size = max(1, int(batch_size))
        _ = max_batch_size  # Kept only for constructor compatibility.
        self._flush_interval = max(0.1, float(flush_interval))
        self._max_queue_size = max(1, int(max_queue_size))
        self._overload_policy = (
            overload_policy
            if overload_policy in {"drop_oldest", "drop_newest", "reject_new"}
            else "drop_oldest"
        )
        self._lock = threading.Lock()
        self._persisted_packets = 0
        self._persisted_alerts = 0
        self._last_retention_cleanup = 0.0
        self._flow_writer = flow_writer
        self._batch_writer = BatchPersistenceWriter(
            self._write_central_batch,
            queue_max=self._max_queue_size,
            overflow_policy=self._overload_policy,
            retry_max=self._max_retries,
            retry_backoff_ms=int(self._retry_backoff_sec * 1000),
            batch_sizes={
                "packet_record": self._batch_size,
                "alert_record": self._batch_size,
            },
            flush_ms={
                "packet_record": int(self._flush_interval * 1000),
                "alert_record": int(self._flush_interval * 1000),
            },
        )

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
            "attribution_reason_unavailable": packet.get(
                "attribution_reason_unavailable"
            ),
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
                "app_confidence": alert.get("app_confidence")
                or packet.get("app_confidence"),
                "protocol_basis": alert.get("protocol_basis")
                or packet.get("protocol_basis"),
                "protocol_notes": alert.get("protocol_notes")
                or packet.get("protocol_notes"),
                "protocol_handshake": alert.get("protocol_handshake")
                or packet.get("protocol_handshake"),
                "protocol_unusual_port": (
                    alert.get("protocol_unusual_port")
                    if alert.get("protocol_unusual_port") is not None
                    else packet.get("protocol_unusual_port")
                ),
                "dns_qname": alert.get("dns_qname") or packet.get("dns_qname"),
                "dns_qtype": (
                    alert.get("dns_qtype")
                    if alert.get("dns_qtype") is not None
                    else packet.get("dns_qtype")
                ),
                "dns_rcode": (
                    alert.get("dns_rcode")
                    if alert.get("dns_rcode") is not None
                    else packet.get("dns_rcode")
                ),
                "http_method": alert.get("http_method") or packet.get("http_method"),
                "http_host": alert.get("http_host") or packet.get("http_host"),
                "http_path": alert.get("http_path") or packet.get("http_path"),
                "http_status": (
                    alert.get("http_status")
                    if alert.get("http_status") is not None
                    else packet.get("http_status")
                ),
                "http_reason": alert.get("http_reason") or packet.get("http_reason"),
                "http_user_agent": alert.get("http_user_agent")
                or packet.get("http_user_agent"),
                "http_content_type": alert.get("http_content_type")
                or packet.get("http_content_type"),
                "sni": alert.get("sni") or packet.get("tls_sni") or packet.get("sni"),
                "tls_version": alert.get("tls_version") or packet.get("tls_version"),
                "tls_alpn": alert.get("tls_alpn")
                or packet.get("tls_alpn")
                or packet.get("alpn"),
                "ja3": alert.get("ja3") or packet.get("ja3"),
                "ja3_str": alert.get("ja3_str") or packet.get("ja3_str"),
                "ja4": alert.get("ja4") or packet.get("ja4"),
                "payload_len": (
                    alert.get("payload_len")
                    if alert.get("payload_len") is not None
                    else packet.get("payload_len")
                ),
                "payload_hex": alert.get("payload_hex") or packet.get("payload_hex"),
                "payload_ascii": alert.get("payload_ascii")
                or packet.get("payload_ascii"),
                "payload_binary_like": (
                    alert.get("payload_binary_like")
                    if alert.get("payload_binary_like") is not None
                    else packet.get("payload_binary_like")
                ),
                "payload_entropy": (
                    alert.get("payload_entropy")
                    if alert.get("payload_entropy") is not None
                    else packet.get("payload_entropy")
                ),
                "payload_printable_ratio": (
                    alert.get("payload_printable_ratio")
                    if alert.get("payload_printable_ratio") is not None
                    else packet.get("payload_printable_ratio")
                ),
                "pid": alert.get("pid") or packet.get("pid"),
                "process_name": alert.get("process_name") or packet.get("process_name"),
                "parent_pid": alert.get("parent_pid") or packet.get("parent_pid"),
                "parent_process_name": alert.get("parent_process_name")
                or packet.get("parent_process_name"),
                "executable_path": alert.get("executable_path")
                or packet.get("executable_path"),
                "attribution_confidence": alert.get("attribution_confidence")
                or packet.get("attribution_confidence"),
                "attribution_reason_unavailable": alert.get(
                    "attribution_reason_unavailable"
                )
                or packet.get("attribution_reason_unavailable"),
                "attribution_source": alert.get("attribution_source")
                or packet.get("attribution_source"),
            }
            for alert in alerts
        ]

        events = [
            {
                "type": "packet_record",
                "payload": packet_row,
                "source": "live_capture",
                "priority": "normal",
            },
            *[
                {
                    "type": "alert_record",
                    "payload": alert_row,
                    "source": "detection_engine",
                    "priority": (
                        "high"
                        if alert_row.get("severity") in {"high", "critical"}
                        else "normal"
                    ),
                }
                for alert_row in alert_rows
            ],
        ]
        self._batch_writer.enqueue_many(events)

    def persist_flow(self, flow: dict[str, Any]) -> None:
        if self._flow_writer is not None:
            self._batch_writer.enqueue(
                "flow_record", flow, source="flow_engine", priority="normal"
            )

    def stats(self) -> dict[str, int | float | str | bool | list[str]]:
        metrics = self._batch_writer.metrics()
        return {
            **metrics,
            "enabled": bool(is_persist_enabled()),
            "max_size": metrics["queue_max"],
            "current_depth": metrics["queue_depth"],
            "queue_size": metrics["queue_depth"],
            "utilization_percent": metrics["queue_utilization_percent"],
            "accepted_writes": metrics["events_received_total"],
            "dropped_writes": metrics["events_dropped_total"],
            "failed_writes": metrics["events_failed_total"],
            "failed_batches": 1 if metrics["events_failed_total"] else 0,
            "persisted_packets": self._persisted_packets,
            "persisted_alerts": self._persisted_alerts,
            "flush_batches": metrics["batches_written_total"],
            "last_flush_ms": metrics["write_latency_avg_ms"],
            "avg_flush_ms": metrics["write_latency_avg_ms"],
            "p95_flush_ms": metrics["write_latency_p95_ms"],
            "flush_errors": 1 if metrics["last_error"] else 0,
            "flush_retries": metrics["retry_total"],
            "queue_high_water_mark": metrics["high_water_mark"],
            "overload_policy": metrics["overflow_policy"],
            "last_error": metrics["last_error"],
            "pressure_reasons": [
                (
                    "persistence_failed_writes"
                    if reason == "persistence_failed_events"
                    else (
                        "persistence_dropped_writes"
                        if reason == "persistence_dropped_events"
                        else reason
                    )
                )
                for reason in metrics["pressure_reasons"]
            ],
        }

    def close(self, timeout_sec: float = 10.0) -> None:
        self._batch_writer.close(timeout_sec=timeout_sec)

    def _write_central_batch(
        self, grouped: dict[str, list[dict[str, Any]]]
    ) -> dict[str, int]:
        packet_rows = [row["payload"] for row in grouped.get("packet_record", [])]
        alert_rows = [row["payload"] for row in grouped.get("alert_record", [])]
        result = (
            insert_batch(packet_rows, alert_rows)
            if packet_rows or alert_rows
            else {"retries": 0}
        )
        flow_rows = [row["payload"] for row in grouped.get("flow_record", [])]
        if flow_rows and self._flow_writer is not None:
            self._flow_writer(flow_rows)
        with self._lock:
            self._persisted_packets += len(packet_rows)
            self._persisted_alerts += len(alert_rows)
        self._run_retention_cleanup()
        return result if isinstance(result, dict) else {"retries": 0}

    def _run_retention_cleanup(self) -> None:
        now = time.time()
        if now - self._last_retention_cleanup < 60.0:
            return
        self._last_retention_cleanup = now
        try:
            from backend.app.services.settings_service import \
                get_settings_snapshot

            cleanup_retention(
                int(get_settings_snapshot().get("retention_minutes") or 0)
            )
        except Exception:
            logger.debug("retention cleanup skipped", exc_info=True)
