from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

from backend.app.bootstrap import ensure_project_root_on_path
from backend.app.services.batch_persistence import BatchPersistenceWriter
from backend.app.services.persistence_ticket import MAX_TRACKED_GROUP_EVENTS, PersistenceTicket
from backend.app.services.persistence_contracts import (
    HistoryStorageUnavailable, PersistenceFlushReceipt, PersistenceWriteOutcome,
)

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
        _ = max_batch_size  # Kept only for constructor compatibility.
        batch_sizes = (
            {"packet_record": batch_size, "alert_record": batch_size}
            if batch_size is not None
            else None
        )
        flush_ms = (
            {
                "packet_record": int(float(flush_interval) * 1000),
                "alert_record": int(float(flush_interval) * 1000),
            }
            if flush_interval is not None
            else None
        )
        retry_backoff_ms = (
            int(float(retry_backoff_sec) * 1000)
            if retry_backoff_sec is not None
            else None
        )
        self._lock = threading.Lock()
        self._persisted_packets = 0
        self._persisted_alerts = 0
        self._last_retention_cleanup = 0.0
        self._flow_writer = flow_writer
        self._batch_writer = BatchPersistenceWriter(
            self._write_central_batch,
            queue_max=max_queue_size,
            overflow_policy=overload_policy,
            retry_max=max_retries,
            retry_backoff_ms=retry_backoff_ms,
            batch_sizes=batch_sizes,
            flush_ms=flush_ms,
            prepare_write=self._prepare_central_batch,
        )

    def persist(self, packet: dict[str, Any], alerts: list[dict[str, Any]]) -> None:
        if not is_persist_enabled():
            return
        self._batch_writer.enqueue_many(self._history_events(packet, alerts))

    def _history_events(self, packet: dict[str, Any], alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        packet_row = {
            "capture_id": packet.get("id"),
            "capture_event_id": packet.get("capture_event_id"),
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
            "service_attribution": packet.get("service_attribution"),
            "service_name": packet.get("service_name"),
            "service_category": packet.get("service_category"),
            "service_domain": packet.get("service_domain"),
            "service_confidence": packet.get("service_confidence"),
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
        return events

    def persist_batch_tracked(
        self, records: list[tuple[dict[str, Any], list[dict[str, Any]]]]
    ) -> PersistenceTicket:
        """Submit one opt-in history write unit, not a per-packet disk wait."""
        if len(records) > MAX_TRACKED_GROUP_EVENTS or not 1 <= sum(
            1 + len(alerts) for _, alerts in records
        ) <= MAX_TRACKED_GROUP_EVENTS:
            raise ValueError('Tracked history batch size is outside the supported bound')
        events = [event for packet, alerts in records for event in self._history_events(packet, alerts)]
        return self._batch_writer.enqueue_many_tracked(events)

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
            "packet_storage_enabled": bool(is_persist_enabled()),
            "alert_storage_enabled": bool(is_persist_enabled()),
            "flow_storage_enabled": bool(self._flow_writer is not None and metrics["persistence_enabled"]),
            "max_size": metrics["queue_max"],
            "current_depth": metrics["queue_depth"],
            "queue_size": metrics["queue_depth"],
            "utilization_percent": metrics["queue_utilization_percent"],
            "accepted_writes": metrics["events_received_total"],
            "dropped_writes": metrics["events_dropped_total"],
            "failed_writes": metrics["events_failed_total"],
            "skipped_writes": metrics["events_skipped_total"],
            "failed_batches": 1 if metrics["events_failed_total"] else 0,
            "persisted_packets": self._persisted_packets,
            "persisted_alerts": self._persisted_alerts,
            "flush_batches": metrics["batches_written_total"],
            "last_flush_ms": metrics["write_latency_last_ms"],
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

    def flush(self, timeout_sec: float = 10.0) -> bool:
        return self.flush_result(timeout_sec).succeeded

    def flush_result(self, timeout_sec: float = 10.0) -> PersistenceFlushReceipt:
        return self._batch_writer.flush_result(timeout_sec=timeout_sec)

    def _write_central_batch(
        self, grouped: dict[str, list[dict[str, Any]]]
    ) -> PersistenceWriteOutcome:
        return self._prepare_central_batch(grouped)()

    def _prepare_central_batch(
        self, grouped: dict[str, list[dict[str, Any]]]
    ) -> Callable[[], PersistenceWriteOutcome]:
        """Own confirmed-step progress for one bounded retry cycle, not restart.

        A callback that raises after committing is unconfirmed and may replay.
        No cross-database transaction or durable deduplication is implied.
        """
        packet_rows = [row["payload"] for row in grouped.get("packet_record", [])]
        alert_rows = [row["payload"] for row in grouped.get("alert_record", [])]
        flow_rows = [row["payload"] for row in grouped.get("flow_record", [])]
        history_done = flow_done = False
        history_skipped = False
        result: dict[str, Any] = {"retries": 0}

        def write() -> PersistenceWriteOutcome:
            nonlocal history_done, flow_done, history_skipped, result
            if not history_done:
                returned = (insert_batch(packet_rows, alert_rows)
                            if packet_rows or alert_rows else {"retries": 0})
                result = returned if isinstance(returned, dict) else {"retries": 0}
                status = result.get('status', 'committed')
                if status == 'unavailable':
                    raise HistoryStorageUnavailable('History connection is unavailable')
                if status not in {'committed', 'disabled'}:
                    raise ValueError('Unrecognized history write status')
                history_skipped = status == 'disabled'
                history_done = True
                with self._lock:
                    if not history_skipped:
                        self._persisted_packets += result.get('packets_inserted', len(packet_rows))
                        self._persisted_alerts += result.get('alerts_inserted', len(alert_rows))
            if not flow_done:
                if flow_rows and self._flow_writer is not None:
                    self._flow_writer(flow_rows)
                flow_done = True
            self._run_retention_cleanup()
            skipped = ((len(packet_rows) + len(alert_rows)) if history_skipped else 0)
            if self._flow_writer is None:
                skipped += len(flow_rows)
            events = len(packet_rows) + len(alert_rows) + len(flow_rows)
            confirmed = (frozenset(kind for kind in grouped if kind in {'packet_record', 'alert_record'})
                         if result.get('status') == 'committed' else frozenset())
            return PersistenceWriteOutcome(events - skipped, skipped, int(result.get('retries', 0)), confirmed)

        return write

    def _run_retention_cleanup(self) -> None:
        now = time.time()
        if now - self._last_retention_cleanup < 60.0:
            return
        self._last_retention_cleanup = now
        try:
            from backend.app.services.settings_service import get_settings_snapshot

            cleanup_retention(
                int(get_settings_snapshot().get("retention_minutes") or 0)
            )
        except Exception:
            logger.debug("retention cleanup skipped", exc_info=True)
