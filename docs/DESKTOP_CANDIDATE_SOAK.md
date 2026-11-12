# Supervised Candidate Soak

This is a 5..30 minute live validation tier before multi-hour acceptance.
It is not a production monitor or an unlimited-duration background job.

```powershell
python scripts/qa/candidate_soak.py --executable '<absolute candidate exe>' --duration 900 --require-vpn-cycle
```

Use the existing independently packaged candidate; no installed app is replaced.
The supervisor checks its build manifest, creates a new scratch workspace and
launches the actual Electron UI with its isolated backend and metadata profile.
Capture is real and must be authorized on the host/network. The test itself does
not change VPN, routes or firewall rules and does not generate network traffic.

## Bounds

- Requested capture: 300..1800 seconds, using monotonic clocks. The supervisor
  deadline includes another 120 seconds for launch, UI checks and shutdown.
- Sampled scratch storage: 512 MiB, including temporary profile, SQLite, journal
  and worker log. Worker log has an additional 2 MiB limit.
- Sampled aggregate process RSS: 2 GiB; this sums shared pages across processes
  and is not unique physical-memory consumption.
- Minimum free disk headroom: 2 GiB during execution, 3 GiB before starting.
- At most 64 observed process identities. Only the owned test tree and observed
  descendants can be terminated on a guard failure.

These are sampled watchdogs, not OS-enforced quotas; brief overshoot is possible.
On a guard failure the run fails, even if its earlier counters looked healthy.
The fresh test workspace is disposable and removed after process cleanup; never
use this cleanup policy on an installed recovery journal.

The short test still rejects durations over 120 seconds unless the supervisor's
matching scratch directory, nonce and bounded policy are present. The long test
extends only its own metadata retention to requested duration plus five minutes,
so the final retained SQLite count can be compared with acknowledgements without
expected retention expiry invalidating the test. Storage remains watchdog-bounded.

## Evidence

Only numeric summaries, fixed stage/status labels and the active UI page are
printed. No domain, IP, interface identity, token, raw bytes or traffic screenshot
is exported. Resource samples are retained in a bounded 128-sample tail. CPU is
sampled across observed processes and reported relative to one CPU core; it may
exceed 100%. API p95 is the bounded last 256 requests, not a whole-run benchmark.

Success requires real acknowledged traffic, zero final pending journal records,
matching accepted/acknowledged/SQLite packet counts, no reported history failure
or drop, no renderer error, working selection/investigation/Auto-follow, normal
acknowledged shutdown and temporary-data removal.

`--require-vpn-cycle` additionally requires observing departure from the first
traffic-bearing interface, return to that same interface, and increasing confirmed
traffic after return. Interface identity stays in worker memory only. Dynamic
profiling counters cannot impersonate a route change. This checks an observed
interface cycle, not an unchanged-interface PPP filter change, public exit-country
policy, or complete validation of every OS/VPN transition.

A missing driver counter remains unknown, not zero loss. A 15-minute success
does not establish several-hour stability or exactly-once stateful analysis.
