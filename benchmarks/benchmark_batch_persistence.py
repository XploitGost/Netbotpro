from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.services.batch_persistence import BatchPersistenceWriter
from benchmarks.benchmark_report import (
    BenchmarkConfig,
    add_common_arguments,
    config_from_args,
    synthetic_alert,
    synthetic_packet,
)


def run_persistence_benchmark(config: BenchmarkConfig) -> dict[str, Any]:
    config = config.normalized()
    event_count = max(1, min(int(config.duration_sec * config.events_per_sec), 50_000))
    written = 0
    batches = 0
    lock = threading.Lock()

    def write_batch(grouped: dict[str, list[dict[str, Any]]]) -> None:
        nonlocal written, batches
        with lock:
            written += sum(len(rows) for rows in grouped.values())
            batches += 1

    writer = BatchPersistenceWriter(
        write_batch,
        enabled=True,
        queue_max=max(100, min(event_count, 5000)),
        overflow_policy="drop_oldest",
        retry_max=1,
        retry_backoff_ms=1,
        batch_sizes={
            "packet_record": 100,
            "flow_record": 50,
            "alert_record": 25,
        },
        flush_ms={
            "packet_record": 20,
            "flow_record": 20,
            "alert_record": 20,
        },
    )
    try:
        for sequence in range(event_count):
            packet = synthetic_packet(sequence, config.flows)
            writer.enqueue("packet_record", packet, source="synthetic_benchmark")
            if sequence % 10 == 0:
                writer.enqueue(
                    "flow_record",
                    {"flow_id": packet["flow_key"], "packets": sequence + 1},
                    source="synthetic_benchmark",
                )
            if (
                config.alert_rate
                and sequence % max(1, config.events_per_sec // config.alert_rate) == 0
            ):
                writer.enqueue(
                    "alert_record",
                    synthetic_alert(sequence, packet),
                    source="synthetic_benchmark",
                )
        flushed = writer.flush(10.0)
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            metrics = writer.metrics()
            if metrics["queue_depth"] == 0:
                break
            time.sleep(0.01)
        metrics = writer.metrics()
    finally:
        writer.close(10.0)
    metrics.update(
        {
            "sink_events_written_total": written,
            "sink_batches_total": batches,
            "manual_flush_completed": flushed,
            "bounded": metrics["queue_depth"] <= metrics["queue_max"],
            "write_latency_ms_avg": metrics["write_latency_avg_ms"],
            "write_latency_ms_p95": metrics["write_latency_p95_ms"],
        }
    )
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark batch persistence.")
    add_common_arguments(parser)
    print(run_persistence_benchmark(config_from_args(parser.parse_args())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
