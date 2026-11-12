# Isolated History-Confirmed Journal Probe

## Scope And Safety

`scripts/qa/journal_history_probe.py` runs the actual `SnifferService`, detection,
flow, publication, history writer and encrypted process-journal path in a fresh
subprocess. Its default capture source is synthetic; `--live` explicitly selects
the system capture provider and Npcap. It does not launch Electron, replace an
installed application, change VPN/routes or generate network requests.

All settings, SQLite databases, logs and journal files use a disposable workspace.
Auto-block and raw-payload capture are disabled there. Only a JSON summary leaves
the worker; packet values, domains, hostnames and raw exception messages are not
included. Scratch data is removed after worker and observed child-process cleanup,
including failed probes. A failed probe's retained journal is test data, not an
installed application's recovery journal.

The supervisor accepts 1..120 seconds and 1..500 synthetic events/second. It
requires at least 512 MiB free scratch space. A sampled 64 MiB storage watchdog,
64-observed-child budget and duration-plus-60-second deadline terminate only the
probe's process tree if exceeded. Disk/RSS peaks are sampled, not hard filesystem
quotas; brief overshoot is possible. No unbounded telemetry file or packet report
is retained. The last 512 completion durations are retained only in memory.

## Run

Use the project's installed Python dependencies on Windows:

```powershell
python scripts/qa/journal_history_probe.py --duration 20 --rate 250
python scripts/qa/journal_history_probe.py --duration 60 --live
```

Live mode honors capture preflight and requires a working capture driver and its
permissions. It does not elevate privileges or bypass preflight. Non-Windows
hosts report that DPAPI is required; they do not fall back to plaintext.

Success requires positive acknowledged traffic, equality of accepted, acknowledged
and stored packet counts, drained journal, and no reported capture/history write
errors or driver buffer drops. Missing driver coverage remains explicitly unknown;
it is not evidence of zero wire loss. A missing/inconsistent counter fails the
history reconciliation. Exit status is nonzero for failure.

`completion_tail_p95_ms` measures history submission/wait and post-commit delivery
for a batch. It excludes capture intake, earlier analysis and queue waiting before
completion starts. `stop_and_flush_ms` covers service Stop and history flush.
The probe is not a UI latency benchmark or full long-duration acceptance test.

## Local Evidence: 2026-11-12

The first live probe exposed `sqlite3.ProgrammingError`: parsed `tls_alpn` is a
list (including the ordinary empty-list case), but SQLite's history column is
TEXT. Synthetic fixtures without parsed ALPN had missed this. The storage
boundary now serializes ALPN lists/tuples to the comma-separated format already
supported by history readers, for both packets and alerts. Input records and
legacy string values remain unchanged; unrelated binding errors still roll back
the complete write group. Tests first reproduced the error, then passed the fix.

After that correction:

| Probe | Live, 60 seconds | Synthetic, 250 events/sec, 20 seconds |
| --- | ---: | ---: |
| Accepted / stored / acknowledged | 1520 / 1520 / 1520 | 5028 / 5028 / 5028 |
| Final pending records | 0 | 0 |
| Sampled peak pending records | 29 | 31 |
| Completion tail p95 | 6.724 ms | 8.670 ms |
| Stop and flush | 432.702 ms | 32.718 ms |
| History failures / drops | 0 / 0 | 0 / 0 |
| Driver buffer drops reported | 0, coverage complete at final sample | Not applicable |
| Sampled temporary bytes | 15126856 | 12268888 |
| Sampled process-tree peak RSS | 249.031 MiB | 128.633 MiB |
| Scratch workspace removed | Yes | Yes |

These are short local observations, not production throughput guarantees. The
installed desktop remains unchanged and history-confirmed acknowledgement remains
opt-in. Route-change recovery, injected slow/failing storage and multi-hour UI
soak remain promotion gates; no exactly-once state or universal lossless capture
claim follows from these results.
