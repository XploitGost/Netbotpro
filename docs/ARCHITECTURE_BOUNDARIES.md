# Architecture boundaries and migration checkpoint

## Source ownership

Git is the intended source of truth. Installed `resources/python-src` is a
deployment copy, not a second development branch. This checkpoint reconciles
reviewed backend changes and preserves the desktop UI overlay sources separately.
Runtime databases, packet journals, tokens, screenshots and executables are not
source artifacts and must not be committed.

## Target boundaries

| Owner | Responsibilities | Boundary |
| --- | --- | --- |
| Capture adapter | OS handles, routing changes, raw buffer, capture counters | Ordered batches and explicit lifecycle/health |
| Analysis core | Parsing, flow state, detection, bounded caches | Metadata records and versioned snapshots |
| Application services | Configuration, orchestration, history, exports, attribution | API models; no frontend or Electron dependency |
| Persistence | Journal, batching, durable storage, retention | Explicit write/ack/drain semantics |
| API and event delivery | Authentication, queries, filtered paging, events | Read-only detached views of core state |
| React UI | Selection, navigation, filters, rendering | API/controller contracts, never compiled-symbol patching |
| Electron shell | Process startup, readiness, normal shutdown | Backend health and graceful drain protocol |

These are target ownership rules, not a claim that every existing module already
enforces them. In particular the large sniffer service and desktop overlay remain
migration work.

## Migration order

First implemented slice: `AnalyzedPacket`, `DeliveryPorts` and `PacketDelivery`
separate the ordered delivery fan-out from the service's analysis step without
introducing queues, skipping redaction or claiming durable acknowledgement.
See [ADR 0001](adr/0001-packet-analysis-delivery-boundary.md).

Second slice: `JournalBatchDelivery` separates preparation/callback/ack ordering
from process capture lifecycle, with stage-specific failures and an explicit
acknowledgement receipt. It does not certify durable downstream writes or prevent
replay of a completed prefix. See [ADR 0002](adr/0002-journal-batch-acknowledgement.md).
Global sequencing, transactional receipts and UI build unification remain open.

`PersistenceFlushReceipt` now distinguishes writer-barrier completion from
timeout/eviction and records observed failure/drop counters. Boolean flush callers
use this explicit result instead of treating any wakeup as successful storage.
See [ADR 0003](adr/0003-persistence-flush-receipts.md). This is not a downstream
crash-atomic commit receipt or a change to capture acknowledgement.

Central persistence now prepares one retry-local operation per batch: history
that returned successfully is not inserted again solely because the separate
flow writer failed. No completion state survives restart and no disk ledger is
added. See [ADR 0004](adr/0004-partial-persistence-retry.md).

Journal occurrence identity now survives reopen and protects retained packet
history rows against replay. It does not merge old IDs, deduplicate alerts/flow
analysis or delay journal acknowledgement until durable history commit.
See [ADR 0005](adr/0005-journal-packet-occurrence-identity.md).

Explicit history outcomes now separate committed processing from intentional skips
and unavailable connections. These diagnostics do not certify remaining legacy
adapters or change journal reclamation. See
[ADR 0006](adr/0006-explicit-history-write-outcomes.md).

Tracked packet/alert groups have process-local completion handles grounded in
explicit adapter category confirmation. This opt-in foundation is not yet wired
to Capture or journal reclamation; see
[ADR 0007](adr/0007-tracked-history-group-receipts.md).

Versioned detector occurrence keys now protect retained identified alert rows
on replay. Unknown provenance remains non-deduplicated; this does not checkpoint
analysis state or change Capture acknowledgement. See
[ADR 0008](adr/0008-versioned-alert-occurrence-keys.md).

1. Establish one reproducible source/build path. Integrate the preserved desktop
   components into the standard frontend before removing the compatibility overlay.
2. Define batch schema, sequence, lifecycle, ownership, error and backpressure
   contracts. Keep runtime and UI queues separate from durable acknowledgement.
3. Separate capture orchestration, analysis state, persistence and read models
   incrementally, with replay parity and lifecycle regression tests at each step.
4. Profile isolated workloads. Consider a Rust implementation behind the batch
   contract only for measured bottlenecks; keep a reference implementation and
   fallback. Do not cross the language boundary once per full packet dictionary.
5. Require a clean-checkout build and continuous real-traffic soak before promotion.

## Current limits

Flow detail compression is lossless and reduces retained fixture state, but its
hot target is not a global memory cap. Active flows and ID catalogs still need
retention design. Short smoke tests do not establish four-hour stability or prove
absence of hardware packet loss. ML alert calibration, crash-atomic persistence
and the complete desktop source migration require further validation.
