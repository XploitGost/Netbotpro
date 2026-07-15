from __future__ import annotations

import argparse
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.services.flow_worker_pool import FlowWorkerPool
from benchmarks.benchmark_report import (
    BenchmarkConfig,
    add_common_arguments,
    config_from_args,
    synthetic_packet,
)


def run_worker_pool_benchmark(config: BenchmarkConfig) -> dict[str, Any]:
    config = config.normalized()
    event_count = max(1, min(int(config.duration_sec * config.events_per_sec), 50_000))
    sequences: dict[str, list[int]] = defaultdict(list)
    worker_threads: set[str] = set()
    lock = threading.Lock()

    def process(packet: dict[str, Any]) -> None:
        time.sleep(0.0001)
        with lock:
            sequences[str(packet["flow_key"])].append(int(packet["sequence"]))
            worker_threads.add(threading.current_thread().name)

    pool = FlowWorkerPool(
        process,
        worker_count=min(4, config.flows),
        queue_max=max(100, min(event_count, 5000)),
        overflow_policy="block_short",
        block_timeout_sec=0.2,
        shutdown_timeout_sec=10.0,
        slow_job_ms=1000.0,
    )
    try:
        accepted = sum(
            1
            for sequence in range(event_count)
            if pool.submit(synthetic_packet(sequence, config.flows))
        )
        drained = pool.wait_until_drained(10.0)
        metrics = pool.stats()
    finally:
        pool.close(10.0)
    metrics.update(
        {
            "benchmark_events_total": event_count,
            "benchmark_accepted_total": accepted,
            "drained": drained,
            "same_flow_order_preserved": all(
                values == sorted(values) for values in sequences.values()
            ),
            "processing_threads_observed": len(worker_threads),
            "parallel_workers_observed": len(worker_threads) > 1,
            "bounded": metrics["queue_depth_total"] <= metrics["queue_max_total"],
            "processing_latency_ms_avg": metrics["avg_processing_latency_ms"],
            "processing_latency_ms_p95": metrics["p95_processing_latency_ms"],
            "processing_latency_ms_max": metrics["max_processing_latency_ms"],
        }
    )
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark flow-aware workers.")
    add_common_arguments(parser)
    print(run_worker_pool_benchmark(config_from_args(parser.parse_args())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
