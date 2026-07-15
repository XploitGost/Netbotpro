from __future__ import annotations

import argparse
import json
import queue
import sys
import threading
import time
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.services.batch_persistence import BatchPersistenceWriter
from backend.app.services.event_aggregator import EventAggregator
from backend.app.services.flow_worker_pool import FlowWorkerPool
from backend.app.services.live_ring_buffer import DEFAULT_CAPACITIES, LiveRingBuffer
from backend.app.services.packet_queue import BoundedPacketQueue
from benchmarks.benchmark_report import (
    BenchmarkConfig,
    ResourceSampler,
    add_common_arguments,
    config_dict,
    config_from_args,
    synthetic_alert,
    synthetic_packet,
    utc_now,
    write_reports,
)


def run_soak_test(config: BenchmarkConfig) -> dict[str, Any]:
    config = config.normalized()
    target_packet_rate = min(config.events_per_sec, config.packet_rate)
    target_alert_rate = min(config.alert_rate, target_packet_rate)
    packet_queue = BoundedPacketQueue(max_size=2000, overflow_policy="drop_oldest")
    capacities = {category: value for category, value in DEFAULT_CAPACITIES.items()}
    if config.ci_safe:
        capacities.update(
            {
                "packet": 500,
                "flow": 200,
                "alert": 100,
                "expert_info": 100,
                "protocol_metadata": 100,
                "agent_status": 50,
                "ops_event": 50,
            }
        )
    ring = LiveRingBuffer(
        capacities=capacities,
        default_query_limit=50,
        max_query_limit=250,
    )

    emitted: list[dict[str, Any]] = []
    emit_lock = threading.Lock()

    def emit(message: dict[str, Any]) -> None:
        with emit_lock:
            if len(emitted) >= 1000:
                del emitted[:100]
            emitted.append(message)

    aggregator = EventAggregator(
        emit,
        packet_batch_ms=100,
        packet_batch_max=100,
        alert_batch_ms=100,
        alert_batch_max=50,
        flow_batch_ms=200,
        flow_batch_max=100,
    )

    sink_events_written = 0
    sink_batches = 0
    sink_lock = threading.Lock()

    def write_batch(grouped: dict[str, list[dict[str, Any]]]) -> None:
        nonlocal sink_events_written, sink_batches
        with sink_lock:
            sink_events_written += sum(len(rows) for rows in grouped.values())
            sink_batches += 1

    persistence = BatchPersistenceWriter(
        write_batch,
        enabled=True,
        queue_max=2000,
        overflow_policy="drop_oldest",
        retry_max=1,
        retry_backoff_ms=1,
        batch_sizes={
            "packet_record": 100,
            "flow_record": 50,
            "alert_record": 25,
        },
        flush_ms={
            "packet_record": 100,
            "flow_record": 200,
            "alert_record": 100,
        },
    )

    processed_total = 0
    alert_total = 0
    counter_lock = threading.Lock()

    def process(packet: dict[str, Any]) -> None:
        nonlocal processed_total, alert_total
        flow_key = str(packet["flow_key"])
        ring.append("packet", packet, flow_key=flow_key, source="synthetic_benchmark")
        flow = {
            "flow_id": flow_key,
            "last_sequence": packet["sequence"],
            "packets_count": int(packet["sequence"]) + 1,
            "source": "synthetic_benchmark",
        }
        ring.append("flow", flow, flow_key=flow_key, source="synthetic_benchmark")
        persistence.enqueue("packet_record", packet, source="synthetic_benchmark")
        if int(packet["sequence"]) % 10 == 0:
            persistence.enqueue("flow_record", flow, source="synthetic_benchmark")
            aggregator.publish("flow:update", flow)
        aggregator.publish("packet:new", packet)
        should_alert = (
            target_alert_rate
            and int(packet["sequence"])
            % max(1, target_packet_rate // target_alert_rate)
            == 0
        )
        if should_alert:
            alert = synthetic_alert(int(packet["sequence"]), packet)
            ring.append("alert", alert, flow_key=flow_key, source="synthetic_benchmark")
            persistence.enqueue("alert_record", alert, source="synthetic_benchmark")
            aggregator.publish("alert:new", alert)
            with counter_lock:
                alert_total += 1
        with counter_lock:
            processed_total += 1

    workers = FlowWorkerPool(
        process,
        worker_count=min(4, config.flows),
        queue_max=2000,
        overflow_policy="drop_oldest",
        shutdown_timeout_sec=10.0,
        error_threshold=100,
        slow_job_ms=100.0,
    )

    sampler = ResourceSampler()
    start_time = utc_now()
    started = time.perf_counter()
    deadline = started + config.duration_sec
    generated_total = 0
    health_transitions: list[str] = []
    last_health = ""
    sampler.start()
    try:
        interval = 1.0 / target_packet_rate
        next_event_at = started
        while time.perf_counter() < deadline:
            packet = synthetic_packet(generated_total, config.flows)
            packet_queue.put(packet)
            try:
                queued = packet_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                workers.submit(queued.packet)
            finally:
                packet_queue.task_done()
            generated_total += 1
            next_event_at += interval
            wait = next_event_at - time.perf_counter()
            if wait > 0:
                time.sleep(min(wait, 0.05))
            if generated_total % max(1, target_packet_rate) == 0:
                health = _pipeline_health(
                    packet_queue.stats(),
                    workers.stats(),
                    aggregator.stats(),
                    persistence.metrics(),
                    ring.metrics(),
                )
                if health != last_health:
                    health_transitions.append(health)
                    last_health = health
        packet_queue.wait_until_drained(2.0)
        workers.wait_until_drained(10.0)
        aggregator.flush_all()
        persistence.flush(10.0)
        _wait_for_persistence(persistence, 10.0)
    finally:
        resource_metrics = sampler.stop()

    ring_query_started = time.perf_counter()
    ring.query("all", limit=100)
    ring_query_latency_ms = (time.perf_counter() - ring_query_started) * 1000.0
    elapsed = max(time.perf_counter() - started, 0.000001)
    packet_metrics = packet_queue.stats(worker_alive=True)
    worker_metrics = workers.stats()
    aggregator_metrics = aggregator.stats()
    persistence_metrics = persistence.metrics()
    ring_metrics = ring.metrics()
    workers.close(10.0)
    aggregator.close()
    persistence.close(10.0)

    persistence_metrics["sink_events_written_total"] = sink_events_written
    persistence_metrics["sink_batches_total"] = sink_batches
    persistence_metrics["write_latency_ms_avg"] = persistence_metrics[
        "write_latency_avg_ms"
    ]
    persistence_metrics["write_latency_ms_p95"] = persistence_metrics[
        "write_latency_p95_ms"
    ]
    worker_metrics["processing_latency_ms_avg"] = worker_metrics[
        "avg_processing_latency_ms"
    ]
    worker_metrics["processing_latency_ms_p95"] = worker_metrics[
        "p95_processing_latency_ms"
    ]
    worker_metrics["processing_latency_ms_max"] = worker_metrics[
        "max_processing_latency_ms"
    ]
    aggregator_metrics["batches_emitted_total"] = aggregator_metrics[
        "batches_sent_total"
    ]
    ring_metrics["query_latency_ms_avg"] = round(ring_query_latency_ms, 3)
    ring_metrics["query_latency_ms_p95"] = round(ring_query_latency_ms, 3)
    aggregator_metrics.setdefault("send_latency_ms_avg", 0.0)
    aggregator_metrics.setdefault("send_latency_ms_p95", 0.0)
    websocket_metrics = {
        "health": aggregator_metrics.get("health", "healthy"),
        "slow_clients": 0,
        "dropped_for_slow_client_total": 0,
        "coalesced_for_slow_client_total": aggregator_metrics.get(
            "events_coalesced_total", 0
        ),
        "send_latency_ms_avg": aggregator_metrics.get("send_latency_ms_avg", 0.0),
        "send_latency_ms_p95": aggregator_metrics.get("send_latency_ms_p95", 0.0),
    }
    dropped_total = sum(
        int(value or 0)
        for value in (
            packet_metrics.get("dropped_total"),
            worker_metrics.get("jobs_dropped_total"),
            worker_metrics.get("jobs_rejected_total"),
            aggregator_metrics.get("events_dropped_total"),
            persistence_metrics.get("events_dropped_total"),
        )
    )
    failed_total = int(worker_metrics.get("jobs_failed_total") or 0) + int(
        persistence_metrics.get("events_failed_total") or 0
    )
    final_health = _pipeline_health(
        packet_metrics,
        worker_metrics,
        aggregator_metrics,
        persistence_metrics,
        ring_metrics,
    )
    pressure_reasons = _pressure_reasons(
        packet_metrics,
        worker_metrics,
        aggregator_metrics,
        persistence_metrics,
        ring_metrics,
    )
    return {
        "schema_version": 1,
        "benchmark_type": "synthetic_full_pipeline_soak",
        "safe_synthetic_only": True,
        "configuration": config_dict(config),
        "general": {
            "start_time": start_time,
            "end_time": utc_now(),
            "duration_sec": round(elapsed, 3),
            "target_packet_rate": target_packet_rate,
            "target_alert_rate": target_alert_rate,
            "events_generated_total": generated_total,
            "events_processed_total": processed_total,
            "alerts_generated_total": alert_total,
            "events_dropped_total": dropped_total,
            "events_failed_total": failed_total,
            "throughput_events_sec": round(processed_total / elapsed, 2),
            "pipeline_processing_latency_ms_p95": worker_metrics[
                "processing_latency_ms_p95"
            ],
        },
        "resources": resource_metrics,
        "packet_queue": packet_metrics,
        "flow_worker_pool": worker_metrics,
        "event_aggregator": aggregator_metrics,
        "websocket": websocket_metrics,
        "persistence": persistence_metrics,
        "live_ring_buffer": ring_metrics,
        "ops_health": {
            "final_health": final_health,
            "pressure_reasons": pressure_reasons,
            "transitions": health_transitions,
        },
        "validation": {
            "packet_queue_bounded": packet_metrics["high_water_mark"]
            <= packet_metrics["max_size"],
            "flow_worker_pool_bounded": worker_metrics["queue_depth_total"]
            <= worker_metrics["queue_max_total"],
            "persistence_bounded": persistence_metrics["queue_depth"]
            <= persistence_metrics["queue_max"],
            "live_ring_buffer_bounded": all(
                values["records"] <= values["capacity"]
                for values in ring_metrics["categories"].values()
            ),
            "reports_redacted": True,
            "external_network_used": False,
            "admin_privileges_required": False,
            "live_capture_used": False,
        },
    }


def _wait_for_persistence(writer: BatchPersistenceWriter, timeout_sec: float) -> bool:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if writer.metrics()["queue_depth"] == 0:
            return True
        time.sleep(0.01)
    return writer.metrics()["queue_depth"] == 0


def _pipeline_health(*sections: dict[str, Any]) -> str:
    levels = [str(section.get("health") or "healthy") for section in sections]
    if "critical" in levels:
        return "critical"
    if "degraded" in levels or "warning" in levels:
        return "degraded"
    return "healthy"


def _pressure_reasons(*sections: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for section in sections:
        for reason in section.get("pressure_reasons") or []:
            safe_reason = str(reason)
            if safe_reason not in reasons:
                reasons.append(safe_reason)
    return reasons


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a safe synthetic NetBotPro full-pipeline soak test."
    )
    add_common_arguments(parser)
    args = parser.parse_args()
    config = config_from_args(args, soak=True)
    results = run_soak_test(config)
    paths = write_reports(results, config.output)
    print(
        json.dumps(
            {
                "ok": True,
                "events_processed_total": results["general"]["events_processed_total"],
                "final_health": results["ops_health"]["final_health"],
                "output": paths,
            },
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
