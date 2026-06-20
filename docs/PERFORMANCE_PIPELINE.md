# Performance Pipeline

NetBotPro added a bounded packet intake queue as the first step of the
performance pipeline. The goal is to prevent capture callbacks from feeding an
unbounded in-memory path when traffic spikes or downstream processing slows.

This is a foundation step, not the complete performance engine.

## Current Pipeline

```text
Capture
-> Bounded Packet Queue
-> Packet Queue Worker
-> Existing Packet Processing
-> Flow / Detection / Persistence / UI
```

The capture provider calls the backend packet callback. That callback copies the
packet metadata into a bounded queue and returns quickly. A single packet queue
worker drains the queue and runs the existing processing path: payload policy,
protocol and detection analysis, flow ingestion, dashboard state updates,
SQLite persistence enqueue, and websocket publishing.

## Why The Queue Exists

Before this step, live capture could push directly into packet processing. That
kept the implementation simple, but it gave the hot path no clear backpressure
boundary. The bounded queue makes the limit explicit and observable:

- memory growth is bounded by `NETBOT_PACKET_QUEUE_MAX_SIZE`;
- overload behavior is controlled by one overflow policy;
- drops are counted and logged;
- queue depth and utilization are exposed in monitoring;
- the worker can be checked during shutdown and health monitoring.

## Configuration

| Variable | Default | Allowed values | Notes |
| --- | --- | --- | --- |
| `NETBOT_PACKET_QUEUE_MAX_SIZE` | `2000` | Positive integer | Maximum packet metadata items waiting for processing. |
| `NETBOT_PACKET_QUEUE_OVERFLOW_POLICY` | `drop_oldest` | `drop_oldest`, `drop_newest` | Behavior when the queue is full. |
| `NETBOT_PACKET_QUEUE_DRAIN_TIMEOUT_SEC` | `5.0` | Positive number | Time allowed for queue drain during shutdown. |

Recommended local values:

```text
NETBOT_PACKET_QUEUE_MAX_SIZE=1000
NETBOT_PACKET_QUEUE_OVERFLOW_POLICY=drop_oldest
NETBOT_PACKET_QUEUE_DRAIN_TIMEOUT_SEC=5.0
```

Recommended heavier-capture starting values:

```text
NETBOT_PACKET_QUEUE_MAX_SIZE=5000
NETBOT_PACKET_QUEUE_OVERFLOW_POLICY=drop_oldest
NETBOT_PACKET_QUEUE_DRAIN_TIMEOUT_SEC=10.0
```

Use `drop_oldest` when the dashboard should favor the freshest network state
during bursts. Use `drop_newest` when preserving the oldest queued packet order
is more important than showing the latest burst. In both modes, drops are not
silent: counters, `last_drop_reason`, health, pressure reasons, and warning logs
record the overload.

## Monitoring Metrics

`/api/monitoring/metrics` exposes a `packet_queue` section:

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
- `dropped_newest_total`
- `high_water_mark`
- `queue_high_water_mark` for compatibility
- `overflow_policy`
- `worker_alive`
- `last_drop_reason`
- `health`

Queue pressure also contributes to top-level `pressure_reasons`:

- `packet_queue_backlog`
- `packet_queue_high_water`
- `packet_queue_dropped_packets`
- `packet_queue_worker_stopped`

Health is `degraded` when utilization is high or drops occur. Health becomes
`critical` when drops are high or the queue worker is not alive.

## Implemented Now

- Bounded packet intake queue.
- `drop_oldest` and `drop_newest` overflow policies.
- Drop counters and high-water mark.
- Last drop reason.
- Warning logs for packet drops.
- Worker liveness metric.
- Monitoring snapshot integration.
- Ops Snapshot UI visibility.
- Backend and frontend tests.

## Intentionally Not Implemented Yet

- Worker pool.
- WebSocket batching.
- Batch persistence.
- Ring buffer storage.
- New protocol decoders.
- Suricata or external IDS engine integration.
- Command/control, remote shell, file collection, Agent raw packet forwarding,
  Agent raw payload forwarding, Agent PCAP forwarding, TLS decryption, MITM, or
  credential collection.

## Next Planned Steps

1. WebSocket batching.
2. Batch persistence.
3. Flow-aware worker pool.
4. Ring buffers.
5. Benchmark and soak tests.
