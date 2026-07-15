# Performance Validation

## Status

This report records Step 7 validation of NetBotPro's existing performance
foundation. It is a safe synthetic benchmark, not a production capacity claim.

| Component | Status |
| --- | --- |
| Bounded Packet Queue | Validated |
| Flow-aware Worker Pool | Validated |
| WebSocket Event Aggregator | Validated |
| Batch Persistence | Validated |
| Live Ring Buffer | Validated with expected bounded eviction |

## Purpose and System Under Test

The suite verifies that pressure is bounded and observable from packet intake
through flow-aware processing, recent-memory storage, realtime aggregation, and
batched persistence. Each stage has a focused benchmark, and
`benchmarks/soak_test_pipeline.py` exercises the integrated path.

```text
Synthetic packet/flow/alert summaries
-> Bounded Packet Intake Queue
-> Flow-aware Worker Pool
-> Live Ring Buffer
-> WebSocket Event Aggregator
-> Batch Persistence
-> Ops health and redacted reports
```

## Methodology and Safety

The July 15, 2026 reference smoke used deterministic synthetic metadata on a
local Windows developer machine. It did not capture traffic, open external
network connections, require Administrator privileges, scan hosts, or store
raw payloads. Report data passed through central redaction before JSON and
Markdown were written.

Configuration:

```text
duration: 10 seconds
events per second: 200
flow keys: 20
profile: ci-safe
live capture: disabled
```

The CI test uses a shorter version and checks structure, bounded state, output
generation, and redaction. It deliberately avoids strict throughput limits so
slower CI operating systems are not treated as failures.

## Reference Results

| Metric | Result |
| --- | ---: |
| Measured duration | 10.001 sec |
| Events generated / processed | 2,000 / 2,000 |
| Alerts generated | 1,000 |
| Pipeline throughput | 199.98 events/sec |
| Dropped / failed events | 0 / 0 |
| Packet queue high-water / capacity | 1 / 2,000 |
| Worker average / p95 / max processing latency | 0.33 / 0.65 / 2.78 ms |
| Aggregator events received / sent | 3,200 / 3,200 |
| Persistence events received / written | 3,200 / 3,200 |
| Persistence batches | 126 |
| Ring records added / evicted | 5,000 / 4,200 |
| Memory start / peak / end | 25.62 / 29.73 / 29.68 MiB |
| CPU average / peak | 9.12% / 49.60% |

These values describe one synthetic run on one machine and may vary. The
important validation result is that every queue remained within capacity,
processing completed without failure, drops remained observable, and the
output stayed bounded.

## Observations

No intake, worker, aggregator, or persistence drops occurred in the reference
run. The final Ops state was `degraded` only because the deliberately small
CI-safe Ring Buffer reached category limits and evicted old records. Pressure
reasons were `live_ring_high_utilization` and
`live_ring_frequent_evictions`. This is expected bounded behavior and confirms
that retention pressure is visible instead of causing unbounded growth.

Process RSS grew by about 4.07 MiB during this short warm-up run and stabilized
below the observed peak at shutdown. A longer, deployment-specific soak is
still required before making memory-retention conclusions.

## Tuning Recommendations

| Workload signal | First tuning action |
| --- | --- |
| Intake drops or sustained queue utilization | Reduce capture pressure or increase `NETBOT_PACKET_QUEUE_MAX_SIZE` within memory limits. |
| Worker backlog across multiple flows | Increase `NETBOT_FLOW_WORKER_COUNT` only when CPU headroom exists. |
| Slow realtime clients | Tune WebSocket batch windows and slow-client policy before raising queue limits. |
| Persistence backlog | Tune batch size/flush interval, then queue capacity; inspect write latency first. |
| Frequent Ring Buffer eviction | Increase only the affected category capacity or accept a shorter live-history window. |

## Limitations

- No real packet capture, PCAP replay, driver pressure, or privileged interface
  was tested.
- No external WebSocket clients or storage service was used.
- The persistence sink was local and safe; host crash durability was not
  measured.
- The reference run is short and synthetic, so it is not a benchmark comparison
  or production sizing certificate.
- Optional ClickHouse or an external metrics backend is not implemented.

## Next Product Phase

The performance foundation is ready to close Step 7. The next recommended
phase is conservative Service Attribution / Destination Intelligence. It must
preserve the existing local-first, redaction, Agent telemetry-only, and Remote
Sensor security boundaries.
