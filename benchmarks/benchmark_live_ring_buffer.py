from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.services.live_ring_buffer import DEFAULT_CAPACITIES, LiveRingBuffer
from benchmarks.benchmark_report import (
    BenchmarkConfig,
    add_common_arguments,
    config_from_args,
    percentile,
    synthetic_packet,
)


def run_live_ring_benchmark(config: BenchmarkConfig) -> dict[str, Any]:
    config = config.normalized()
    event_count = max(1, min(int(config.duration_sec * config.events_per_sec), 50_000))
    packet_capacity = max(10, min(event_count // 2 or 1, 5000))
    capacities = {category: 10 for category in DEFAULT_CAPACITIES}
    capacities["packet"] = packet_capacity
    ring = LiveRingBuffer(
        capacities=capacities,
        default_query_limit=50,
        max_query_limit=100,
    )
    append_latencies: list[float] = []
    query_latencies: list[float] = []
    started = time.perf_counter()
    for sequence in range(event_count):
        packet = synthetic_packet(sequence, config.flows)
        item_started = time.perf_counter()
        ring.append(
            "packet",
            packet,
            flow_key=packet["flow_key"],
            source="synthetic_benchmark",
        )
        append_latencies.append((time.perf_counter() - item_started) * 1000.0)
        if sequence % 100 == 0:
            query_started = time.perf_counter()
            ring.query("packet", limit=50)
            query_latencies.append((time.perf_counter() - query_started) * 1000.0)
    ring.query("packet", limit=1000)
    elapsed = max(time.perf_counter() - started, 0.000001)
    metrics = ring.metrics()
    metrics.update(
        {
            "benchmark_events_total": event_count,
            "benchmark_throughput_events_sec": round(event_count / elapsed, 2),
            "append_latency_ms_avg": round(
                sum(append_latencies) / len(append_latencies), 3
            ),
            "append_latency_ms_p95": percentile(append_latencies, 0.95),
            "query_latency_ms_avg": (
                round(sum(query_latencies) / len(query_latencies), 3)
                if query_latencies
                else 0.0
            ),
            "query_latency_ms_p95": percentile(query_latencies, 0.95),
            "bounded": metrics["categories"]["packet"]["records"]
            <= metrics["categories"]["packet"]["capacity"],
        }
    )
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark Live Ring Buffer.")
    add_common_arguments(parser)
    print(run_live_ring_benchmark(config_from_args(parser.parse_args())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
