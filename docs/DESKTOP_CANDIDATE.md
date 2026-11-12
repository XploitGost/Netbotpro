# Isolated Windows Desktop Candidate

This is a validation package, not an installed-app replacement or a release.
The normal Electron entry and installed profile are unchanged.

## Build

Install the repository's Python, frontend and desktop dependencies first, then
commit source changes so the candidate has an unambiguous source revision:

```powershell
python scripts/release/build_desktop_candidate.py
```

The builder creates a new revision/timestamp directory under
`%LOCALAPPDATA%/NetBotCandidates/` (a short path avoids legacy Windows path limits
inside scientific-library bundles). It packages a fresh PyInstaller backend and both
Vite entries, then builds an unpacked Electron candidate. It never copies the old
security-build backend or stages over `packaging/runtime/backend` or an installed
app. `candidate.json` records its source revision and executable path. Build
dependencies must already exist; the builder does not install global software.

Build steps have 15-minute deadlines and a sampled 3 GiB workspace budget.
Starting requires 5 GiB free space, and the build stops below 2 GiB free. Sampling
can overshoot briefly. Failed artifacts are retained for diagnosis, not deleted
automatically. Each build creates a new directory; this is not an unlimited
retention manager. Do not repeatedly rebuild without reviewing disk usage.

## Candidate Profile

The candidate bootstrap selects `desktop.html`, sets its own user-data directory,
and overrides history, flow, journal, cache and runtime paths within that profile.
It rejects ordinary profile paths and inherited backend/dev-server overrides.
The default is `%APPDATA%/netbot-candidate-preview`; tests explicitly use a new
`netbot-candidate-smoke-*` temporary profile instead.

New profiles start with metadata-only capture, auto-block and autostart disabled,
15-minute metadata retention and sampling rate one. Candidate history-confirmed
journaling is explicitly enabled. This does not change installed/default capture
policy or establish exactly-once analysis. The candidate is not a production soak
configuration or a hard disk quota.

## Explicit Live Test

```powershell
$env:NETBOT_CANDIDATE_EXE = '<absolute executable path from candidate.json>'
$env:NETBOT_SMOKE_PYTHON_BIN = '<absolute Python executable>'
$env:NETBOT_CANDIDATE_DURATION = '60'
node frontend/desktop-reference/test-candidate-capture.mjs
```

This starts real capture through the candidate's UI. Run only on a network you
are authorized to inspect and with a working Npcap driver. It does not change VPN,
routes, firewall rules or generate test traffic. Duration is restricted to 15..120
seconds, with a sampled 128 MiB temporary-profile budget. It exercises packet
selection, investigation, Auto-follow and Stop, then verifies acknowledged history
against SQLite rows after a normal acknowledged app shutdown.

Only numeric counters are printed. Raw traffic screenshots, domains and packet
records are not exported. The temporary test profile is removed after the test;
an emergency deadline can terminate only the owned candidate process tree. This
test fixture's data is disposable, unlike an installed recovery journal.

An interface-change count does not prove a complete VPN-return scenario. Such a
scenario requires an actual user-approved route change while capture is active.
Missing driver statistics remain unknown, not proof of zero wire loss. A short
successful capture does not establish multi-hour stability.

## Local Evidence: 2026-11-12

The independently built candidate used source revision
`a9512a398dde95622ed7c7ae5b2db18669e45023`, a fresh packaged backend and Electron
45.2.3. The complete build workspace, including intermediate files, was
857,832,152 bytes. An initial long-checkout build exposed a Windows path-length
failure while copying a scientific-library binary; the short candidate root
resolved it without changing OS settings or using an old packaged backend.

The final live run used the improved page-aware test harness:

| Observation | Measured |
| --- | ---: |
| Capture plus UI checks | 122 seconds |
| Accepted / acknowledged / SQLite packet rows | 10,189 / 10,189 / 10,189 |
| Final journal pending | 0 |
| Sampled peak pending | 128 |
| Failed / dropped history writes | 0 / 0 |
| Reported driver buffer drops | 0; final statistics coverage complete |
| Renderer errors | 0 |
| Sampled local API p95 | 40 ms |
| Packet selection through investigation findings | 175 ms |
| Stop completion | 473 ms |
| Sampled temporary profile peak | 28,535,468 bytes |
| Acknowledged app shutdown and temporary-profile removal | Passed |

These API and selection samples include test overhead and are not controlled
throughput/latency benchmarks. Memory/CPU and multi-hour growth still need
dedicated profiling. Driver counters do not prove zero wire loss.

In a separate 22-second run with one observed interface change, all 1,170
accepted packets were acknowledged and stored, final pending was zero, and UI
checks passed. A longer transition observation recorded two interface switches
with positive progressing capture counters, but its UI check failed because the
test assumed Live Monitor stayed selected while another page was active.
The harness now explicitly navigates back before selecting a packet and records
the active page with numeric samples. That failed UI assertion is not counted as
a successful complete VPN-return acceptance run. The final 122-second run had
no interface changes, so it does not close the full VPN-return/long-soak gate.

No installed application or installed profile was replaced. Only numeric
summaries were exported; real traffic screenshots and raw records were not kept.
