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
- At most 64 concurrently retained live process identities. Exited helpers and
  their CPU baselines are retired rather than exhausting a lifetime-count budget.
  Only the owned test tree and observed live descendants can be terminated.

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

## Initial Findings

The first 900-second attempt was stopped by its supervisor at 433.73 seconds:
the initial guard incorrectly counted 65 lifetime process identities rather than
concurrent live processes. It is a failed run, not an application crash or a
completed soak. Its last minute sample had 8,892 accepted/acknowledged records,
zero pending, two observed interface changes with return and further confirmed
traffic, no renderer error and no reported driver buffer drop. Scratch peak was
30,762,289 bytes and was removed. Final Stop/SQLite reconciliation was not reached.

Review also found duplicate interface discovery inside one `/interfaces` response:
the service enumerated interfaces, then provider preflight enumerated them again.
`SystemCaptureProvider.preflight_for_interfaces` now reuses the same fresh snapshot;
other providers retain their existing fallback. The service no longer mutates the
provider-owned payload when adding preflight. This avoids the second enumeration
without a new stale cache or a slower route-refresh interval. Focused regressions
cover single-snapshot readiness and compatibility.

## Completed Local Run: 2026-11-12

The fresh package from `08c68198cb6dce7e69800ff92cdc44f1e0706a9d` completed
the corrected supervised run. Capture and final UI checks took 903 seconds;
supervisor startup, checks and cleanup took 911.03 seconds in total.

| Observation | Measured |
| --- | ---: |
| Accepted / acknowledged / retained SQLite rows | 48,771 / 48,771 / 48,771 |
| Final / sampled peak journal pending | 0 / 3,866 |
| Interface switches | 2 |
| Departure, return and further confirmed traffic | Observed |
| History failed / dropped writes | 0 / 0 |
| Reported driver buffer drops | 0; final coverage complete |
| Renderer errors | 0 |
| Bounded API tail p95 | 22.11 ms |
| Selection through investigation findings | 354 ms |
| Stop | 675 ms |
| Sampled scratch peak | 75,444,505 bytes |
| Sampled aggregate process RSS peak | 1,134.74 MiB |
| Sampled aggregate CPU, one-core basis | 28.12% |
| Sampled active process peak | 10 |
| Lifetime observed process identities | 126 |
| Profile and supervisor workspace removed | Yes |

The active-process guard stayed enabled. Most later identities were short-lived
capture-backend probes (117 sampled identities), not 126 simultaneously live
processes. Interface enumeration is now shared within one API response, but these
periodic backend probes still exist; their CPU cost needs separate attribution.

Aggregate RSS for samples with nine active processes increased from 950.77 MiB
at 154.2 seconds to 1,049.82 MiB at 894.5 seconds (99.05 MiB). Shared pages are
counted more than once; this is neither unique memory nor proof of a leak.
Do not extrapolate a flat memory curve or several-hour stability from this run.
Memory ownership, retained state/caches and probe overhead are follow-up gates.

The user also exercised paused Auto-follow during capture. The harness returned
to Live Monitor for its final selection and resumed follow before Stop. Its
inspection check confirms finding-panel navigation, not exhaustive protocol
decoding or absence of every handled HTTP error. No real packet screenshot or
raw traffic report was exported, and the installed app remained unchanged.

Windows CI additionally exposed a test-isolation race: build-guard unit tests
mocked the shared `time.monotonic`, allowing other background threads to consume
their finite fake-clock sequence. The mocks now replace only the candidate
module's dependency references, leaving global clocks/process APIs unchanged.
