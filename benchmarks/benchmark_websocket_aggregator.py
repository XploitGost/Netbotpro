from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.services.event_aggregator import EventAggregator
from benchmarks.benchmark_report import (
    BenchmarkConfig,
    add_common_arguments,
    config_from_args,
    percentile,
    synthetic_alert,
    synthetic_packet,
)


def run_websocket_benchmark(config: BenchmarkConfig) -> dict[str, Any]:
    config = config.normalized()
    event_count = max(1, min(int(config.duration_sec * config.events_per_sec), 50_000))
    emitted: list[dict[str, Any]] = []
    emit_latencies: list[float] = []

    def emit(message: dict[str, Any]) -> None:
        started = time.perf_counter()
        emitted.append(message)
        emit_latencies.append((time.perf_counter() - started) * 1000.0)

    aggregator = EventAggregator(
        emit,
        packet_batch_ms=10_000,
        packet_batch_max=100,
        alert_batch_ms=10_000,
        alert_batch_max=50,
        flow_batch_ms=10_000,
        flow_batch_max=50,
    )
    try:
        for sequence in range(event_count):
            packet = synthetic_packet(sequence, config.flows)
            aggregator.publish("packet:new", packet)
            if (
                config.alert_rate
                and sequence % max(1, config.events_per_sec // config.alert_rate) == 0
            ):
                aggregator.publish("alert:new", synthetic_alert(sequence, packet))
            if sequence % 10 == 0:
                aggregator.publish(
                    "flow:update",
                    {"flow_id": packet["flow_key"], "packets": sequence + 1},
                )
        aggregator.flush_all()
        metrics = aggregator.stats()
    finally:
        aggregator.close()
    metrics.update(
        {
            "batches_emitted_total": metrics["batches_sent_total"],
            "emitted_messages_total": len(emitted),
            "send_latency_ms_avg": (
                round(sum(emit_latencies) / len(emit_latencies), 3)
                if emit_latencies
                else 0.0
            ),
            "send_latency_ms_p95": percentile(emit_latencies, 0.95),
            "bounded": all(
                metrics[key] <= limit
                for key, limit in (
                    ("pending_packet_events", aggregator.packet_batch_max),
                    ("pending_alert_events", aggregator.alert_batch_max),
                    ("pending_flow_events", aggregator.flow_batch_max),
                )
            ),
        }
    )
    return metrics


# Keep a stage-oriented name for callers that do not model a real WebSocket client.
run_event_aggregator_benchmark = run_websocket_benchmark


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark websocket batching.")
    add_common_arguments(parser)
    print(run_websocket_benchmark(config_from_args(parser.parse_args())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
