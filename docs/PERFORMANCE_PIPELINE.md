# Performance Pipeline

NetBotPro now has a bounded packet intake queue as the first engine-level
performance hardening step. This page documents the current foundation only.
It is not the complete performance pipeline yet.

## Why The Queue Was Added

Live capture can receive packets faster than downstream analysis, persistence,
or websocket publishing can process them. The bounded intake queue creates a
clear pressure boundary between capture and the existing processing path.

It was added to:

- prevent unbounded memory growth during capture bursts;
- make packet drops visible instead of silent;
- protect UI, flow analysis, detection, and storage from direct capture
  pressure;
- create the foundation for bounded batching and flow-aware worker lanes;
- expose queue pressure through `/api/monitoring/metrics` and Ops Snapshot.

## Current Pipeline

```text
Capture
-> Bounded Packet Intake Queue
-> Flow-aware Worker Pool
-> Existing Packet Processing
-> Live Ring Buffer
-> Bounded Batch Persistence (packets, alerts, flow snapshots)
-> Event Aggregator
-> Batched WebSocket Updates
-> Flow / Detection / Persistence / UI
```

The capture callback copies packet metadata into `BoundedPacketQueue` and
returns quickly. Its dispatcher sends accepted metadata to bounded flow-aware
worker lanes. Each lane runs the existing processing path: payload policy,
protocol metadata, flow ingestion, detection, and dashboard state. Redacted
summaries then enter the Live Ring Buffer before persistence enqueue and
websocket publishing. The Event Aggregator batches high-frequency realtime
updates before websocket fan-out.

## Environment Variables

### NETBOT_PACKET_QUEUE_MAX_SIZE

Purpose: maximum number of packet metadata items allowed to wait for processing.

Default: `2000`

Allowed values: any positive integer. Invalid or tiny values are clamped by the
queue implementation to at least `1`.

Examples:

```text
NETBOT_PACKET_QUEUE_MAX_SIZE=1000
NETBOT_PACKET_QUEUE_MAX_SIZE=5000
```

Recommended local/small value: `1000`

Recommended heavier-capture starting value: `5000`

Warning: a larger queue can absorb bursts, but it also allows more memory use
and can increase how long stale packets wait before processing.

### NETBOT_PACKET_QUEUE_OVERFLOW_POLICY

Purpose: behavior when the queue is already full.

Default: `drop_oldest`

Allowed values:

- `drop_oldest`
- `drop_newest`

Examples:

```text
NETBOT_PACKET_QUEUE_OVERFLOW_POLICY=drop_oldest
NETBOT_PACKET_QUEUE_OVERFLOW_POLICY=drop_newest
```

Recommended local/small value: `drop_oldest`

Recommended heavier-capture starting value: `drop_oldest`

Warning: both policies drop packet metadata under pressure. Drops are counted,
logged, and exposed in metrics, but dropped packets cannot be reconstructed by
the live pipeline.

### NETBOT_PACKET_QUEUE_DRAIN_TIMEOUT_SEC

Purpose: maximum time to wait for the packet queue to drain during shutdown.

Default: `5.0`

Allowed values: positive number of seconds.

Examples:

```text
NETBOT_PACKET_QUEUE_DRAIN_TIMEOUT_SEC=5.0
NETBOT_PACKET_QUEUE_DRAIN_TIMEOUT_SEC=10.0
```

Recommended local/small value: `5.0`

Recommended heavier-capture starting value: `10.0`

Warning: a longer timeout gives queued packets more time to finish processing
when stopping capture, but it can make shutdown feel slower.

## Overflow Policies

### drop_oldest

`drop_oldest` removes the oldest queued packet when the queue is full, then
accepts the newest packet.

This is better for keeping recent live visibility in Monitor, Flows, and Ops
Snapshot. It may lose older queued context during bursts.

Counters updated:

- `accepted_total` increments when the new packet is accepted;
- `dropped_total` increments;
- `dropped_oldest_total` increments;
- `last_drop_reason` becomes `queue_full_drop_oldest`.

### drop_newest

`drop_newest` rejects the newest packet when the queue is full and keeps the
already queued packets in order.

This is better for preserving queued order. It may miss recent packets under
pressure.

Counters updated:

- `accepted_total` does not increment for the rejected packet;
- `dropped_total` increments;
- `dropped_newest_total` increments;
- `last_drop_reason` becomes `queue_full_drop_newest`.

## Metrics Exposed

`/api/monitoring/metrics` exposes a compact `packet_queue` object:

- `enabled`
- `max_size`
- `current_depth`
- `queue_size` for compatibility
- `utilization_percent`
- `accepted_total`
- `accepted_packets` for compatibility
- `dropped_total`
- `dropped_packets` for compatibility
- `dropped_oldest_total`
- `dropped_oldest` for compatibility
- `dropped_newest_total`
- `dropped_newest` for compatibility
- `high_water_mark`
- `queue_high_water_mark` for compatibility
- `overflow_policy`
- `worker_alive`
- `last_drop_reason`
- `health`
- `pressure_reasons`

The packet queue contributes these top-level operational pressure reasons:

- `packet_queue_backlog`
- `packet_queue_high_water`
- `packet_queue_dropped_packets`
- `packet_queue_worker_stopped`

Health behavior:

- `healthy`: queue depth is normal, no meaningful drops, and the worker is
  alive.
- `degraded`: queue utilization is high, high-water mark is near capacity, or
  drops occurred.
- `critical`: packet queue worker is not alive, or dropped packets are
  significant.

Queue metrics are counters and fixed status values only. They do not include
packet payloads, credentials, cookies, authorization headers, sessions, or
tokens.

## Ops Snapshot Visibility

The Operations UI shows:

- queue health;
- current depth and max size;
- utilization percent;
- accepted packets;
- dropped packets;
- dropped oldest and dropped newest;
- high-water mark;
- overflow policy;
- worker status;
- safe last drop reason.

Recommended actions are emitted when utilization is high, drops occur, the
worker is not alive, or the high-water mark approaches capacity.

## Batch Persistence / Storage Backpressure

Step 4 places redacted packet, alert, and flow records behind one
`BatchPersistenceWriter`. Producers enqueue a standard envelope with `type`,
`timestamp`, `payload`, `source`, and `priority`. Existing SQLite bulk APIs then
write each group transactionally. High and critical alerts flush early. Audit
records and user-requested report exports intentionally remain synchronous.

```text
Packet Processing / Flow Engine / Detection
-> Central Redaction
-> Bounded Persistence Queue
-> Size, Time, Priority, Manual, or Shutdown Flush
-> SQLite Batch Transaction
```

| Variable | Default | Purpose |
| --- | ---: | --- |
| `NETBOT_PERSISTENCE_BATCH_ENABLED` | `true` | Async batching; `false` uses synchronous compatibility writes. |
| `NETBOT_PERSISTENCE_PACKET_BATCH_SIZE` | `500` | Packet size flush. |
| `NETBOT_PERSISTENCE_PACKET_FLUSH_MS` | `1000` | Maximum packet wait. |
| `NETBOT_PERSISTENCE_FLOW_BATCH_SIZE` | `250` | Flow size flush. |
| `NETBOT_PERSISTENCE_FLOW_FLUSH_MS` | `1500` | Maximum flow wait. |
| `NETBOT_PERSISTENCE_ALERT_BATCH_SIZE` | `100` | Alert size flush. |
| `NETBOT_PERSISTENCE_ALERT_FLUSH_MS` | `1000` | Maximum normal-alert wait. |
| `NETBOT_PERSISTENCE_AGENT_BATCH_SIZE` | `100` | Reserved summary-history size. |
| `NETBOT_PERSISTENCE_AGENT_FLUSH_MS` | `3000` | Reserved summary-history window. |
| `NETBOT_PERSISTENCE_QUEUE_MAX` | `5000` | Bounded pending write units. |
| `NETBOT_PERSISTENCE_RETRY_MAX` | `3` | Retries after the initial attempt. |
| `NETBOT_PERSISTENCE_RETRY_BACKOFF_MS` | `250` | Exponential retry base. |
| `NETBOT_PERSISTENCE_OVERFLOW_POLICY` | `drop_oldest` | `drop_oldest`, `drop_newest`, or `reject_new`. |

Tune batch windows before enlarging the queue for heavier authorized capture.
A larger queue costs memory and increases record age. Every drop is counted,
logged with a fixed safe reason, and exposed in Ops.

Invalid booleans, integers, batch sizes, flush windows, retry values, and
overflow policies fall back to the defaults above. Retry is finite and uses
exponential backoff. `drop_oldest` keeps recent work, `drop_newest` preserves
queued order, and `reject_new` explicitly refuses new work. All three policies
increment visible drop metrics when pressure causes loss.

`/api/monitoring/metrics` exposes the clean `persistence` fields:

- `enabled`, `health`, `queue_depth`, `queue_max`, and `utilization_percent`;
- `batches_written_total`, `events_received_total`, and
  `events_written_total`;
- `events_dropped_total`, `events_failed_total`, and `retry_total`;
- `last_flush_at`, safe `last_error`, and safe `last_drop_reason`;
- `write_latency_ms_avg`, `write_latency_ms_p95`, and `backlog_age_ms`;
- `pressure_reasons`.

Health is `healthy` for normal latency and backlog with no meaningful loss,
`degraded` for high utilization, repeated retry, slow writes, old backlog, or
initial loss, and `critical` for a stopped worker, near-full queue, repeated
terminal failures, or significant drops. Persistence pressure contributes to
overall Ops health. Metrics never expose queued payloads.

The Ops panel renders every field above and gives focused actions for growing
backlog, slow disk/database writes, failed writes, and dropped events.

Packet rows, flow snapshots, and alerts are the integrated high-pressure paths.
Protocol metadata travels inside the redacted packet/flow records. Agent
heartbeat and telemetry categories are supported by the envelope, but the
existing reliable summary-only Agent storage path is intentionally unchanged.
Reports stay synchronous so callers receive a definite result. Audit stays
outside batching, writes immediately under its ordering lock, and is tested for
ordered redacted output.

This step does not add database sharding, ClickHouse, benchmark claims, or a
new retention engine. Agent history remains on its existing safe summary path.

## Flow-aware Worker Pool

Step 5 places a bounded processing stage after packet intake and before packet,
flow, and DPI analysis. The intake queue protects capture from immediate
downstream pressure. The worker pool independently protects CPU-bound processing
and makes worker backlog, failures, drops, and latency visible.

TCP and UDP packets use a canonical bidirectional key built from the transport
protocol and normalized endpoint/port pairs. Reverse-direction packets therefore
select the same worker. Other protocols use normalized IP endpoints plus the
protocol. Incomplete metadata uses a deterministic fallback lane and increments
`unknown_flow_key_total` without logging packet contents.

Each stable key is hashed to one FIFO worker lane. Packets from one flow preserve
submission order. Different flows can map to different workers and process in
parallel. Hash collisions are safe: they reduce parallelism but do not corrupt
ordering. Existing FlowEngine and dashboard locks continue to protect shared
state.

| Variable | Default | Allowed values | Purpose |
| --- | ---: | --- | --- |
| `NETBOT_FLOW_WORKERS_ENABLED` | `true` | boolean | Enable flow-aware dispatch; `false` keeps the existing direct processing path. |
| `NETBOT_FLOW_WORKER_COUNT` | `4` | `1` to `64` | Number of fixed worker lanes. |
| `NETBOT_FLOW_WORKER_QUEUE_MAX` | `2000` | positive integer | Total bounded capacity distributed across worker lanes. |
| `NETBOT_FLOW_WORKER_OVERFLOW_POLICY` | `drop_oldest` | `drop_oldest`, `drop_newest`, `reject_new`, `block_short` | Behavior when the selected lane is full. |
| `NETBOT_FLOW_WORKER_SHUTDOWN_TIMEOUT_SEC` | `5` | positive seconds | Maximum graceful drain wait. |
| `NETBOT_FLOW_WORKER_ERROR_THRESHOLD` | `25` | positive integer | Repeated failure/drop threshold for critical health. |
| `NETBOT_FLOW_WORKER_SLOW_JOB_MS` | `100` | positive milliseconds | Slow processing threshold. |

Invalid configuration falls back to conservative defaults. `drop_oldest` keeps
the latest live work, `drop_newest` preserves queued work, `reject_new` refuses
the incoming job explicitly, and `block_short` waits for only a small bounded
interval. No policy busy-waits or retries indefinitely.

The `flow_worker_pool` monitoring section exposes worker counts, total queue
depth/capacity, utilization, received/processed/failed/dropped/rejected counts,
unknown keys, slow jobs, average/p95/max latency, per-worker counters, safe last
error/drop fields, and pressure reasons. Metrics contain no packet payload,
header, credential, cookie, token, session, or secret data.

Health is `healthy` under normal backlog and latency, `degraded` for growing
backlog, initial drops/failures, or slow jobs, and `critical` for missing workers,
near-full queues, repeated failures/drops, or extreme latency. These signals
contribute to overall Ops health and focused recommended actions.

## WebSocket Batching / Event Aggregator

Step 3 adds a backend Event Aggregator between packet processing and websocket
delivery. It collects short bursts of realtime packet, alert, flow, dashboard,
Agent, and ops events, then sends compact delta payloads to the frontend.

Target flow:

```text
Processed Packet / Alert / Flow
-> Event Aggregator
-> Batch Window
-> Compact Delta Payload
-> WebSocket Send
-> Frontend Incremental Update
```

Payload types:

- `packet_batch`: packet event envelopes in `events`.
- `alert_batch`: alert event envelopes in `events`.
- `flow_delta`: flow update envelopes in `updates`.
- `dashboard_summary`: latest coalesced dashboard summary.
- `agent_status_batch`: Agent status envelopes in `agents`.
- `ops_health_update`: coalesced operational health.

The old event envelope is preserved inside batch payloads where possible, so
existing packet and alert UI logic can keep working.

### WebSocket Environment Variables

| Variable | Default | Allowed values | Purpose |
| --- | --- | --- | --- |
| `NETBOT_WS_PACKET_BATCH_MS` | `500` | Positive integer milliseconds | Packet batch flush window. |
| `NETBOT_WS_PACKET_BATCH_MAX` | `250` | Positive integer | Packet batch flush size. |
| `NETBOT_WS_ALERT_BATCH_MS` | `500` | Positive integer milliseconds | Alert batch flush window. |
| `NETBOT_WS_ALERT_BATCH_MAX` | `100` | Positive integer | Alert batch flush size. |
| `NETBOT_WS_FLOW_BATCH_MS` | `1000` | Positive integer milliseconds | Flow delta flush window. |
| `NETBOT_WS_FLOW_BATCH_MAX` | `200` | Positive integer | Flow delta flush size. |
| `NETBOT_WS_SUMMARY_BATCH_MS` | `1000` | Positive integer milliseconds | Dashboard and ops summary coalescing window. |
| `NETBOT_WS_AGENT_BATCH_MS` | `5000` | Positive integer milliseconds | Agent/fleet status batch window. |
| `NETBOT_WS_CLIENT_QUEUE_MAX` | `1000` | Positive integer | Per-client websocket outgoing queue cap. |
| `NETBOT_WS_SLOW_CLIENT_POLICY` | `coalesce` | `coalesce`, `drop_oldest`, `drop_newest` | Slow-client queue behavior. |

For heavier authorized capture, increase batch windows before increasing queue
sizes if the browser is overloaded.

### Slow Client Protection

Each websocket client has a bounded outgoing queue. A slow browser cannot grow
backend memory without limit.

Policies:

- `coalesce`: remove an older queued message and keep the newest update.
- `drop_oldest`: remove the oldest queued websocket message.
- `drop_newest`: reject the newest websocket message.

Slow-client counters track dropped events, coalesced events, queue depth, send
latency, and safe last-drop reasons. Shutdown flushes pending aggregated events
and cancels pending batch timers.

### Event Aggregator Metrics

`/api/monitoring/metrics` exposes `event_aggregator`:

- `enabled`
- `packet_batch_ms`
- `packet_batch_max`
- `alert_batch_ms`
- `alert_batch_max`
- `flow_batch_ms`
- `flow_batch_max`
- `summary_batch_ms`
- `agent_batch_ms`
- `pending_packet_events`
- `pending_alert_events`
- `pending_flow_events`
- `batches_sent_total`
- `events_received_total`
- `events_sent_total`
- `events_coalesced_total`
- `events_dropped_total`
- `websocket_batch_size_avg`
- `last_batch_at`
- `last_drop_reason`
- `health`
- `pressure_reasons`

It also exposes `websocket`:

- `clients`
- `slow_clients`
- `client_queue_max`
- `client_queue_depth_max`
- `send_latency_ms_avg`
- `send_latency_ms_p50`
- `send_latency_ms_p95`
- `send_errors_total`
- `dropped_for_slow_client_total`
- `coalesced_for_slow_client_total`
- `last_drop_reason`
- `health`
- `pressure_reasons`

Health behavior:

- `healthy`: normal send latency, no meaningful drops, no slow clients.
- `degraded`: slow clients, coalescing, drops, or high send latency.
- `critical`: severe websocket queue pressure or repeated send failures.

Metrics contain counters and fixed reasons only. They do not include payloads,
credentials, cookies, authorization headers, sessions, secrets, or tokens.

### Frontend Behavior

The frontend processes `packet_batch` and `alert_batch` incrementally, appending
new rows to bounded live lists instead of reloading the session. Flow,
dashboard, ops, and Agent updates are treated as deltas or coalesced summaries.

Live frontend buffers remain bounded:

- `MAX_LIVE_PACKETS=2000`
- `MAX_LIVE_ALERTS=1000`
- `MAX_LIVE_FLOWS=2000`

Table virtualization remains a later step.

## Live Ring Buffer

`LiveRingBuffer` provides a bounded, thread-safe window of recent live analysis
data after packet/flow/DPI processing and central redaction. It prevents the
Inspect and operational read paths from depending on an unbounded in-memory
list while preserving recent context across WebSocket bursts.

Current capture integration stores four useful categories:

- packet summaries, maximum `5000`;
- flow updates, maximum `2000`;
- alerts, maximum `1000`;
- Expert Info records, maximum `1000`.

Protocol metadata, Agent status, and ops event buffers are configured and
bounded for compatible internal use, but are not force-fed by this step. Their
defaults are `2000`, `1000`, and `1000` records. All capacities have safe
fallbacks and can never become unlimited.

When a category reaches capacity, the oldest record is evicted before the new
record is appended. `NETBOT_LIVE_RING_TTL_SECONDS=0` means capacity-only
eviction; a positive value also prunes expired records. Append and query
operations use a short reentrant lock and copy/redact payloads before storage.
Raw payload fields are removed from ring records even when capture policy
permits a guarded forensic workflow.

Read-only endpoints:

- `GET /api/live/recent` supports bounded `type`, `limit`, `flow_key`, and
  `since` queries;
- `GET /api/live/ring/metrics` exposes counters and safe health fields;
- `GET /api/monitoring/metrics` includes the same `live_ring_buffer` section.

Both endpoints use the existing trusted-client and local-token dependencies.
Oversized limits are capped at `NETBOT_LIVE_RING_MAX_QUERY_LIMIT` and counted.
The Ring Buffer complements rather than replaces the Event Aggregator:
WebSocket batching controls delivery pressure, while the ring controls recent
in-memory history. Batch Persistence still owns durable storage pressure, and
the Flow-aware Worker Pool still owns parallel processing pressure.

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `NETBOT_LIVE_RING_ENABLED` | `true` | Enable bounded recent live storage. |
| `NETBOT_LIVE_RING_PACKET_MAX` | `5000` | Packet summary capacity. |
| `NETBOT_LIVE_RING_FLOW_MAX` | `2000` | Flow update capacity. |
| `NETBOT_LIVE_RING_ALERT_MAX` | `1000` | Alert capacity. |
| `NETBOT_LIVE_RING_EXPERT_MAX` | `1000` | Expert Info capacity. |
| `NETBOT_LIVE_RING_PROTOCOL_MAX` | `2000` | Protocol summary capacity. |
| `NETBOT_LIVE_RING_AGENT_MAX` | `1000` | Agent status capacity. |
| `NETBOT_LIVE_RING_OPS_MAX` | `1000` | Operational event capacity. |
| `NETBOT_LIVE_RING_DEFAULT_QUERY_LIMIT` | `250` | Default recent-result limit. |
| `NETBOT_LIVE_RING_MAX_QUERY_LIMIT` | `2000` | Hard API result cap. |
| `NETBOT_LIVE_RING_TTL_SECONDS` | `0` | Optional TTL; zero disables TTL pruning. |

Metrics include enabled/health state, total records/capacity/utilization,
added/evicted/dropped totals, query and query-limit counters, safe timestamps,
safe error type, per-category utilization, and fixed pressure reason enums.
High utilization, frequent evictions, or capped queries degrade health; an
internal read/write error is critical and contributes to overall Ops health.

## Current Limitations

This is not the complete performance engine yet.

Not implemented yet:

- Benchmark / Soak Tests;
- Optional ClickHouse or external metrics backend.

This step also does not add command/control, remote shell, file collection,
Agent raw packet forwarding, Agent raw payload forwarding, Agent PCAP
forwarding, TLS decryption, MITM, credential collection, auto-block/IPS
behavior, or AI autonomous actions.

## Next Planned Steps

1. Benchmark and Soak Tests
2. Performance Validation Report
3. Service Attribution / Destination Intelligence
4. Incident / Correlation Engine
5. Read-only AI Analyst

### Recorded Product Direction

After the remaining performance work, NetBotPro will add conservative Service
Attribution / Destination Intelligence. It will correlate process metadata
with DNS, TLS SNI, HTTP Host, QUIC-visible metadata, ASN, and local service
fingerprints. Missing or weak evidence must remain `Unknown / Encrypted`.

Incident correlation follows attribution, and a read-only AI Analyst follows
incident quality validation. None of these roadmap items authorize TLS
decryption, MITM, credential collection, command/control, autonomous actions,
or Agent raw packet, payload, or PCAP forwarding.
