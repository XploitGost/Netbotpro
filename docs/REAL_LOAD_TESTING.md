# Real Load And Long Soak Testing

This guide documents Step 11 validation for NetBotPro's bounded performance
pipeline. The tools use safe local synthetic metadata by default. They do not
capture live traffic, require Administrator/root privileges, open external
network connections, or export raw payloads.

## Purpose

Real load and long soak validation checks whether CPU, RAM, packet intake,
flow workers, WebSocket batching, persistence, live ring buffers, service
attribution, and incident correlation stay bounded and visible under realistic
workload shapes.

The current validation is a sizing aid, not a production capacity guarantee.
Run the longer profiles on the same hardware and operating system that will be
used for authorized deployments.

## Load Profiles

| Profile | Duration | Events/sec | Flows | WebSocket clients | Target |
| --- | ---: | ---: | ---: | ---: | --- |
| `light_desktop` | 5 min | 100 | 20 | 1 | Very low pressure. |
| `normal_desktop` | 15 min | 250 | 75 | 2 | Stable CPU/RAM and no unbounded growth. |
| `heavy_desktop` | 30 min | 500 | 150 | 3 | Bounded pressure allowed; no crash or unbounded memory. |
| `server_medium` | 60 min | 1000 | 300 | 5 | Stable server-like pressure. |
| `stress_short` | 5 min | 2500 | 600 | 6 | Pressure must be visible and bounded; drops can be acceptable. |

`--ci-safe` caps duration, rate, flows, and clients so CI remains fast.
Long profiles are manual only.

## CI-Safe Benchmark

```powershell
python benchmarks\long_soak_runner.py `
  --profile light_desktop `
  --duration-sec 5 `
  --events-per-sec 100 `
  --flows 10 `
  --websocket-clients 1 `
  --sample-interval-sec 0.25 `
  --ci-safe `
  --output .runtime\benchmarks\ci-safe-real-load
```

Expected output:

- `benchmark_results.json`
- `benchmark_summary.md`
- `resource_timeseries.csv`

All report content passes through central redaction.

## Desktop Tests

Five-minute desktop check:

```powershell
python benchmarks\long_soak_runner.py `
  --profile light_desktop `
  --output .runtime\benchmarks\light-desktop
```

Thirty-minute heavier desktop check:

```powershell
python benchmarks\long_soak_runner.py `
  --profile heavy_desktop `
  --sample-interval-sec 2 `
  --output .runtime\benchmarks\heavy-desktop
```

## Server-Medium Test

```powershell
python benchmarks\long_soak_runner.py `
  --profile server_medium `
  --sample-interval-sec 5 `
  --max-memory-growth-mb 300 `
  --max-cpu-avg-percent 85 `
  --output .runtime\benchmarks\server-medium
```

Run this only on hardware where a one-hour local synthetic soak is acceptable.

## PCAP Replay Argument Handling

The runner accepts PCAP replay arguments so an authorized offline replay harness
can be wired in later without changing the report format:

```powershell
python benchmarks\long_soak_runner.py `
  --profile light_desktop `
  --duration-sec 60 `
  --pcap C:\Authorized\sample.pcap `
  --pcap-loop `
  --pcap-speed-multiplier 2 `
  --output .runtime\benchmarks\pcap-replay-check
```

The repository does not include sensitive or copyrighted PCAP files. The Step
11 runner does not export raw payloads.

## Interpreting Reports

`healthy` means the stage stayed inside normal bounded ranges.

`degraded` means pressure was visible, such as high utilization, bounded
evictions, coalesced realtime events, or backlog. This can be acceptable during
stress testing when it is explained in the report.

`critical` means a worker stopped, failures were significant, queues were near
capacity, or a threshold was exceeded.

Drops mean a bounded queue applied its configured overflow policy. Drops are
not hidden; they appear in counters, pressure reasons, and recommendations.

Live ring evictions mean old in-memory summaries were removed to preserve a
hard memory cap. This is expected when the ring reaches category capacity.

## Memory And CPU Signals

The report includes memory start, end, peak, growth, growth slope, stabilization
classification, CPU average, CPU p95, CPU peak, and sustained CPU pressure.
Process CPU peak can exceed `100%` on multi-core runners, so average and p95 are
usually better stability signals than one short spike. Short runs can include
normal warm-up growth. Treat memory-leak warnings as a signal to repeat a
longer profile before changing production settings.

## Safe Tuning

- Packet queue drops: reduce capture pressure, increase
  `NETBOT_PACKET_QUEUE_MAX_SIZE` carefully, or use stronger hardware.
- Flow worker backlog with CPU headroom: increase `NETBOT_FLOW_WORKER_COUNT`.
- Flow worker backlog with high CPU: reduce capture load or use a stronger CPU.
- WebSocket pressure: reduce UI client count, lower refresh load, or tune
  `NETBOT_WS_SLOW_CLIENT_POLICY`.
- Persistence backlog: tune batch size/time windows or use faster disk.
- Live ring evictions: increase only affected category limits if RAM allows.
- Incident spam: review correlation thresholds and time windows.

Do not use unsafe tuning such as TLS decryption, MITM, credential collection,
browser cookie inspection, or bypassing OS protections.

## Hardware And OS Notes

Windows desktop validation should be run with the same Npcap and privilege
model used in real operation, but the benchmark itself does not require live
capture. Linux/macOS runs are useful for backend sizing but do not replace
Windows desktop smoke for packaged releases.

## Authorized Use

Use NetBotPro only on systems, accounts, servers, and networks where you have
explicit permission. Step 11 validation is local and synthetic by default, and
the Agent boundary remains summary-only.
