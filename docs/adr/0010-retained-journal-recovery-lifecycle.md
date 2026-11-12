# ADR 0010: Retained-journal recovery lifecycle

Status: implemented; history-confirmed mode remains opt-in.

## Observed Failure

A real SQLite lock in an isolated service probe caused the tracked history write
to fail, correctly preventing acknowledgement and retaining the encrypted journal.
However, `SnifferService.stop()` treated pending on-disk records as if the producer
or consumer were still active. It refused to detach the stopped session. Repeated
Stop, Start and service close could not recover without abandoning the runtime.

## Decision

Keep `ProcessCaptureSession.shutdown_ready()` unchanged: it certifies stopped
resources and zero pending metadata. Add a separate `recovery_ready()` condition
for an unsuccessful, retained journal. All of these must be true:

- A journal delivery failure stage is recorded.
- The journal's closed snapshot has a positive integer pending-record count.
- The producer is dead and the consumer completion event is set.
- IPC is closed and the journal connection has actually been released.

No active producer/consumer or open journal can pass this condition. It is not a
commit receipt or a success/drain flag. Normal healthy status polling avoids the
additional producer check by short-circuiting on absent failure state.

After Stop has joined/closed resources, the service may detach a session satisfying
either the unchanged drain condition or this separate recovery condition. It keeps
the final critical status, error, pending count and `journal_retained_for_replay`
marker. No journal row is acknowledged, deleted or rewritten by this release.

Start uses the existing reset/lifecycle lock, then opens the same configured
journal. History-confirmed mode now requires a persistence barrier before reset
even when an injected flow adapter does not use deferred snapshots. This settles
pending late writes before new analysis. Failed or unavailable barriers still
block restart. Known packet/alert occurrence keys retain their existing replay
deduplication guarantees and limits.

`prepare_exit()` can allow exit after resources stop and the persistence barrier
settles while encrypted records remain on disk. Its response still carries the
critical error, pending count and replay marker: `exit_prepared` means safe to
close resources, not that every captured record reached history. An active writer
or capture process still blocks that path. Reopening a service can replay the
retained journal; it must not be cleaned up as disposable application data.

## Fault Verification

The disposable probe now supports four synthetic-capture fault scenarios:

- `locked`: a second SQLite connection holds `BEGIN IMMEDIATE`; the scratch
  writer's shortened busy timeout/retry budget forces a real failure, then the
  lock is released and the same service replays retained occurrences.
- `locked-reopen`: the same failure, then old service workers close and a new
  service opens the retained journal and history in the same test worker process.
- `late-commit`: a gated adapter outlives a short completion wait. No premature
  acknowledgement occurs; the late write commits and subsequent replay remains
  unique in packet history.
- `slow-stop`: a gated history write keeps normal Stop waiting. Releasing it lets
  the existing consumer finish and drain before Stop returns.

Faults affect only scratch settings/databases. Direct probe-worker invocation
outside its supervised temporary workspace is rejected before loading settings.
Tests reconcile accepted-new plus retained counts with acknowledgements and
distinct stored packet occurrences, preserve historical failure diagnostics,
recover original occurrence identities and confirm final journal drain/cleanup.

## Limits

This adds no automatic retry loop, recovery daemon, route-switch policy, journal
deletion or language migration. Start remains an explicit action. Stateful
analysis/publication may replay and is not exactly-once. The reopen probe recreates
service and capture processes, not an entire desktop/OS power-cycle. Real VPN
switches, power loss, broader disk failures and multi-hour UI soak remain gates.
