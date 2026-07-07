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
- create the foundation for future batching and worker-pool work;
- expose queue pressure through `/api/monitoring/metrics` and Ops Snapshot.

## Current Pipeline

```text
Capture
-> Bounded Packet Intake Queue
-> Packet Queue Worker
-> Existing Packet Processing
-> Event Aggregator
-> Batched WebSocket Updates
-> Flow / Detection / Persistence / UI
```

The capture callback copies packet metadata into `BoundedPacketQueue` and
returns quickly. A single packet queue worker drains the queue and sends each
packet through the existing processing path: payload policy, protocol metadata,
flow ingestion, detection, dashboard state, persistence enqueue, and websocket
publishing. The Event Aggregator then batches high-frequency realtime updates
before websocket fan-out so the browser does not receive one message for every
processed packet.

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

## Current Limitations

This is not the complete performance engine yet.

Not implemented yet:

- Flow-aware Worker Pool;
- Batch Persistence;
- Live Ring Buffer;
- Benchmark / Soak Tests;
- Optional ClickHouse or external metrics backend.

This step also does not add command/control, remote shell, file collection,
Agent raw packet forwarding, Agent raw payload forwarding, Agent PCAP
forwarding, TLS decryption, MITM, credential collection, auto-block/IPS
behavior, or AI autonomous actions.

## Next Planned Steps

1. Batch Persistence
2. Flow-aware Worker Pool
3. Live Ring Buffer
4. Benchmark and Soak Tests
5. Performance Validation Report
