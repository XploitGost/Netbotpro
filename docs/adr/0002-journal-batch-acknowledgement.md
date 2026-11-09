# ADR 0002: Journal batch acknowledgement boundary

Status: incremental source refactor; not crash-atomic downstream persistence.

## Context

The process capture reader previously owned both child lifecycle and the loop
that prepares a journal batch, invokes analysis and acknowledges the journal.
Preparation, callback and acknowledgement exceptions all appeared as analysis
errors. A completed callback was easy to mistake for a durable storage receipt.

## Decision

`JournalBatchDelivery` owns only the synchronous prepare/callback/ack sequence.
`ProcessCaptureSession` still owns reading, stop/drain, counters and child control.
The coordinator imports neither the journal implementation nor analysis, process,
thread, queue, database or API implementations. No new queue or worker is added.

Preparation runs once, callbacks run in input order, and acknowledgement is called
only after every callback returns. A `BatchReceipt` is returned only after the
acknowledgement callback returns. It is not a downstream durable commit receipt:
some analysis delivery ports still enqueue persistence or handle errors internally.

Failures carry the stage and completed callback prefix length without packet
contents. The session stops as before and retains the legacy aggregate error
counter. Preparation/analysis failures do not invoke acknowledgement. An
acknowledgement exception is reported as **unconfirmed**, not proof that the
transaction did or did not commit. No automatic retry or skip is introduced.

`journal_acknowledged_records` counts records whose batch acknowledgement returned
in this session; `ipc_delivered` retains its existing completed-callback meaning.
The former is null outside journal mode. These are not wire-capture or durable
storage counters; replay of an old journal need not match current producer intake.
`journal_failure_stage` distinguishes preparation, analysis and acknowledgement.
Status snapshots are diagnostic, not an atomic conservation equation.

## Replay And Limits

A failed batch can contain a prefix with side effects already applied. Restart
replays the whole retained batch, including that prefix. Exactly-once delivery,
deduplication and downstream transactional receipts remain open. Batch IDs remain
the existing local SQLite journal IDs, not global packet sequence numbers.

Tests cover ordering, every failure stage, completed-prefix accounting, no implicit
retry, real encrypted journal reopen/replay, final producer commit after an empty
read, child lifecycle, overflow and normal stop/drain.

Before changing acknowledgement semantics, define idempotent downstream identities
and a durable persistence receipt, then test crash/restart at each boundary.
