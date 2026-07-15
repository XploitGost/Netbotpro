from __future__ import annotations

import argparse
import json
import statistics
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import psutil

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.services.redaction import redact_sensitive_data


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def percentile(values: Iterable[float], percent: float) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * percent)))
    return round(ordered[index], 3)


@dataclass(frozen=True)
class BenchmarkConfig:
    duration_sec: float = 30.0
    events_per_sec: int = 1000
    flows: int = 100
    packet_rate: int = 900
    alert_rate: int = 100
    output: str = ".runtime/benchmarks/latest"
    profile: str = "ci-safe"
    ci_safe: bool = True
    live_capture: bool = False

    def normalized(self) -> "BenchmarkConfig":
        duration_max = 30.0 if self.ci_safe else 3600.0
        events_max = 10_000 if self.ci_safe else 100_000
        return BenchmarkConfig(
            duration_sec=max(0.01, min(float(self.duration_sec), duration_max)),
            events_per_sec=max(1, min(int(self.events_per_sec), events_max)),
            flows=max(1, min(int(self.flows), 100_000)),
            packet_rate=max(1, min(int(self.packet_rate), events_max)),
            alert_rate=max(0, min(int(self.alert_rate), events_max)),
            output=str(self.output or ".runtime/benchmarks/latest"),
            profile=str(self.profile or "ci-safe")[:40],
            ci_safe=bool(self.ci_safe),
            live_capture=False,
        )


def synthetic_packet(sequence: int, flows: int) -> dict[str, Any]:
    flow_index = sequence % max(1, flows)
    local_octet = flow_index % 250 + 1
    remote_octet = flow_index % 200 + 1
    return {
        "id": f"benchmark-packet-{sequence}",
        "sequence": sequence,
        "src": f"10.20.0.{local_octet}",
        "dst": f"198.51.100.{remote_octet}",
        "sport": 20_000 + flow_index % 40_000,
        "dport": 443 if flow_index % 3 else 53,
        "proto": "TCP" if flow_index % 3 else "UDP",
        "app_protocol": "TLS" if flow_index % 3 else "DNS",
        "length": 128 + sequence % 1300,
        "flow_key": f"benchmark-flow-{flow_index}",
        "source": "synthetic_benchmark",
    }


def synthetic_alert(sequence: int, packet: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"benchmark-alert-{sequence}",
        "packet_id": packet["id"],
        "flow_id": packet["flow_key"],
        "severity": "medium" if sequence % 10 else "high",
        "attack_type": "synthetic_validation_signal",
        "source": "synthetic_benchmark",
    }


class ResourceSampler:
    def __init__(self, interval_sec: float = 0.05) -> None:
        self._process = psutil.Process()
        self._interval_sec = max(0.01, float(interval_sec))
        self._stop = threading.Event()
        self._memory: list[int] = []
        self._cpu: list[float] = []
        self._thread: threading.Thread | None = None
        self._memory_start = int(self._process.memory_info().rss)

    def start(self) -> None:
        self._process.cpu_percent(interval=None)
        self._thread = threading.Thread(
            target=self._sample,
            name="netbotpro-benchmark-resource-sampler",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> dict[str, float | int]:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        memory_end = int(self._process.memory_info().rss)
        memory_values = [self._memory_start, *self._memory, memory_end]
        return {
            "memory_start_bytes": self._memory_start,
            "memory_peak_bytes": max(memory_values),
            "memory_end_bytes": memory_end,
            "memory_growth_bytes": memory_end - self._memory_start,
            "cpu_percent_avg": (
                round(statistics.mean(self._cpu), 2) if self._cpu else 0.0
            ),
            "cpu_percent_peak": round(max(self._cpu), 2) if self._cpu else 0.0,
        }

    def _sample(self) -> None:
        while not self._stop.wait(self._interval_sec):
            self._memory.append(int(self._process.memory_info().rss))
            self._cpu.append(float(self._process.cpu_percent(interval=None)))


def report_status(results: dict[str, Any]) -> dict[str, str]:
    mapping = {
        "Bounded Packet Queue": "packet_queue",
        "Flow-aware Worker Pool": "flow_worker_pool",
        "WebSocket Event Aggregator": "event_aggregator",
        "Batch Persistence": "persistence",
        "Live Ring Buffer": "live_ring_buffer",
    }
    return {
        label: "validated" if isinstance(results.get(key), dict) else "needs follow-up"
        for label, key in mapping.items()
    }


def write_reports(
    results: dict[str, Any],
    output: str | Path,
    *,
    write_json: bool = True,
    write_markdown: bool = True,
) -> dict[str, str]:
    destination = Path(output)
    destination.mkdir(parents=True, exist_ok=True)
    safe_results = redact_sensitive_data(results)
    paths: dict[str, str] = {}
    if write_json:
        json_path = destination / "benchmark_results.json"
        json_path.write_text(
            json.dumps(safe_results, indent=2, ensure_ascii=True, default=str) + "\n",
            encoding="utf-8",
        )
        paths["json"] = str(json_path)
    if write_markdown:
        markdown_path = destination / "benchmark_summary.md"
        markdown_path.write_text(render_markdown(safe_results), encoding="utf-8")
        paths["markdown"] = str(markdown_path)
    return paths


def render_markdown(results: dict[str, Any]) -> str:
    general = results.get("general") or {}
    resources = results.get("resources") or {}
    statuses = report_status(results)
    lines = [
        "# NetBotPro Synthetic Performance Summary",
        "",
        "> This report uses local synthetic metadata only. It does not capture or transmit network traffic.",
        "",
        "## Run Summary",
        "",
        "| Metric | Result |",
        "| --- | ---: |",
        f"| Duration | {float(general.get('duration_sec') or 0):.3f} sec |",
        f"| Events generated | {int(general.get('events_generated_total') or 0)} |",
        f"| Events processed | {int(general.get('events_processed_total') or 0)} |",
        f"| Events dropped | {int(general.get('events_dropped_total') or 0)} |",
        f"| Events failed | {int(general.get('events_failed_total') or 0)} |",
        f"| Throughput | {float(general.get('throughput_events_sec') or 0):.2f} events/sec |",
        f"| Peak memory | {int(resources.get('memory_peak_bytes') or 0)} bytes |",
        f"| Memory growth | {int(resources.get('memory_growth_bytes') or 0)} bytes |",
        f"| Average CPU | {float(resources.get('cpu_percent_avg') or 0):.2f}% |",
        "",
        "## Performance Foundation Status",
        "",
    ]
    lines.extend(f"- {label}: **{status}**" for label, status in statuses.items())
    lines.extend(
        [
            "",
            "## Pipeline Metrics",
            "",
            "| Stage | Health | Processed / Written | Dropped / Evicted | Utilization |",
            "| --- | --- | ---: | ---: | ---: |",
            _stage_row(
                "Packet Queue",
                results.get("packet_queue") or {},
                "accepted_total",
                "dropped_total",
            ),
            _stage_row(
                "Flow Worker Pool",
                results.get("flow_worker_pool") or {},
                "jobs_processed_total",
                "jobs_dropped_total",
            ),
            _stage_row(
                "Event Aggregator",
                results.get("event_aggregator") or {},
                "events_sent_total",
                "events_dropped_total",
            ),
            _stage_row(
                "Batch Persistence",
                results.get("persistence") or {},
                "events_written_total",
                "events_dropped_total",
            ),
            _stage_row(
                "Live Ring Buffer",
                results.get("live_ring_buffer") or {},
                "records_added_total",
                "records_evicted_total",
            ),
            "",
            "## Ops Health",
            "",
            f"- Final state: **{(results.get('ops_health') or {}).get('final_health', 'unknown')}**",
            f"- Pressure reasons: {', '.join((results.get('ops_health') or {}).get('pressure_reasons') or []) or 'none'}",
            "",
            "## Interpretation",
            "",
            "Results are machine-dependent and are not production capacity promises. Drops and evictions are explicit bounded-pressure behavior. Validate with authorized workload traces before production sizing.",
            "",
        ]
    )
    return "\n".join(lines)


def _stage_row(
    label: str, metrics: dict[str, Any], processed_key: str, dropped_key: str
) -> str:
    return (
        f"| {label} | {metrics.get('health', 'unknown')} | "
        f"{int(metrics.get(processed_key) or 0)} | "
        f"{int(metrics.get(dropped_key) or 0)} | "
        f"{float(metrics.get('utilization_percent') or 0):.2f}% |"
    )


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--duration-sec", type=float, default=30.0)
    parser.add_argument("--events-per-sec", type=int, default=1000)
    parser.add_argument("--flows", type=int, default=100)
    parser.add_argument("--packet-rate", type=int, default=900)
    parser.add_argument("--alert-rate", type=int, default=100)
    parser.add_argument("--output", default=".runtime/benchmarks/latest")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Generate JSON output (generated by default).",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Generate Markdown output (generated by default).",
    )
    parser.add_argument(
        "--profile", choices=("ci-safe", "local", "heavy"), default="ci-safe"
    )
    parser.add_argument("--no-live-capture", action="store_true", default=True)
    parser.add_argument("--ci-safe", action="store_true")


def config_from_args(
    args: argparse.Namespace, *, soak: bool = False
) -> BenchmarkConfig:
    ci_safe = bool(args.ci_safe or args.profile == "ci-safe")
    duration = args.duration_sec
    if soak and args.duration_sec == 30.0 and not ci_safe:
        duration = 300.0
    return BenchmarkConfig(
        duration_sec=duration,
        events_per_sec=args.events_per_sec,
        flows=args.flows,
        packet_rate=args.packet_rate,
        alert_rate=args.alert_rate,
        output=args.output,
        profile=args.profile,
        ci_safe=ci_safe,
        live_capture=False,
    ).normalized()


def config_dict(config: BenchmarkConfig) -> dict[str, Any]:
    return asdict(config.normalized())


__all__ = [
    "BenchmarkConfig",
    "ResourceSampler",
    "add_common_arguments",
    "config_dict",
    "config_from_args",
    "percentile",
    "render_markdown",
    "synthetic_alert",
    "synthetic_packet",
    "utc_now",
    "write_reports",
]
