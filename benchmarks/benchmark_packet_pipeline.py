from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.services.packet_queue import BoundedPacketQueue
from benchmarks.benchmark_report import (
    BenchmarkConfig,
    add_common_arguments,
    config_from_args,
    percentile,
    synthetic_packet,
)


def run_packet_queue_benchmark(config: BenchmarkConfig) -> dict[str, Any]:
    config = config.normalized()
    event_count = max(1, min(int(config.duration_sec * config.packet_rate), 50_000))
    queue_max = max(10, min(event_count // 2 or 1, 5000))
    packet_queue = BoundedPacketQueue(max_size=queue_max, overflow_policy="drop_oldest")
    latencies_ms: list[float] = []
    started = time.perf_counter()
    queue_logger = logging.getLogger("backend.app.services.packet_queue")
    previous_disabled = queue_logger.disabled
    queue_logger.disabled = True
    try:
        for sequence in range(event_count):
            item_started = time.perf_counter()
            packet_queue.put(synthetic_packet(sequence, config.flows))
            latencies_ms.append((time.perf_counter() - item_started) * 1000.0)
    finally:
        queue_logger.disabled = previous_disabled
    while not packet_queue.empty():
        packet_queue.get(timeout=0.1)
        packet_queue.task_done()
    elapsed = max(time.perf_counter() - started, 0.000001)
    metrics = packet_queue.stats(worker_alive=True)
    metrics.update(
        {
            "benchmark_events_total": event_count,
            "benchmark_throughput_events_sec": round(event_count / elapsed, 2),
            "intake_latency_ms_avg": round(sum(latencies_ms) / len(latencies_ms), 3),
            "intake_latency_ms_p95": percentile(latencies_ms, 0.95),
            "intake_latency_ms_max": round(max(latencies_ms), 3),
            "bounded": metrics["high_water_mark"] <= metrics["max_size"],
        }
    )
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark bounded packet intake.")
    add_common_arguments(parser)
    config = config_from_args(parser.parse_args())
    print(run_packet_queue_benchmark(config))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
