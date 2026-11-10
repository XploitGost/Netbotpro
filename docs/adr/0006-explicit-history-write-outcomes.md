# ADR 0006: Explicit history write outcomes

Status: adapter-result correctness, not durable journal acknowledgement.

## Context

The history adapter returned zero inserted rows for disabled persistence, a missing
connection and a successful duplicate-only transaction. Central batching treated
all three as successful writes. Regressions reproduced both disabled/missing-
connection cases returning successful flushes and incrementing written events.

## Decision

The SQLite history adapter now returns `HistoryWriteResult`: `committed` only
after commit returns, `disabled` when persistence is intentionally off, or
`unavailable` when enabled storage has no connection. Counts and retry fields
remain available to legacy dictionary callers; exceptions still propagate.

Central prepared writes distinguish these outcomes:

- Committed duplicate-only work is confirmed processing with zero new rows.
- Disabled history is an intentional skip, not a successful history write and
  not a storage fault. The same batch can still write its flow records.
- Unavailable history raises a payload-free typed error and uses the existing
  bounded retry policy. History completion is not cached until an outcome is
  known. Already-successful history is still not replayed on later flow failure.

`PersistenceWriteOutcome` carries adapter-confirmed processed event counts,
intentional skip counts and adapter retries. The batch writer validates the counts
against its prepared group. Synchronous and worker paths count skipped events
separately; all-skipped groups do not increment written batches.
All-skipped groups also do not create write-latency samples or clear a preceding
storage error/failure streak. A later confirmed write can clear that current error.
The existing `events_written_total` describes confirmed processing, not newly inserted rows;
packet/alert insertion counters retain the adapter's actual row counts.

Skipped events are exposed as `events_skipped_total`, its persistence-prefixed
alias and `skipped_writes`. Intentional skips alone do not imply a database fault
or degrade storage health. Flush receipts now include skip counters before/after
the observation interval; new skips cannot be certified as successful writes.
A later clean flush can complete without erasing skip history. A synchronous
enqueue that skips work returns false; a later flush does not re-adjudicate it.

## Compatibility And Limits

Legacy adapters returning `None` or retry dictionaries still retain implicit
success-on-return semantics. This does not certify those adapters as durable.
Flow callbacks also retain their existing return contract. Whole-batch terminal
failure accounting remains conservative after partial side effects.

There is no new queue, schema, file, retry policy or journal acknowledgement rule.
No skip is automatically retried as a database fault, and no disabled history is
silently enabled. This does not restore skipped data or add per-event durable
receipts. Existing boolean flush callers may need their retry path when a new
skip is observed; exit/retention policy is not inferred from a success boolean.

Before delaying journal reclamation, migrate the remaining adapter contracts and
define policy for disabled history, alert identities and durable batch receipts.

## Verification

Tests reproduce and fix both false-success paths, distinguish duplicate commits,
cover temporary connection recovery before flow delivery, mixed disabled history
and flow retry, skip visibility without false health errors, synchronous/worker
accounting and invalid/incomplete typed outcomes. Existing partial-write, redaction,
flush and lifecycle tests remain compatibility gates.
