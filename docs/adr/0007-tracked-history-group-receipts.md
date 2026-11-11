# ADR 0007: Tracked history-group receipts

Status: opt-in completion primitive; normal capture/journal acknowledgement unchanged.

## Context

A successful flush observes one interval. It cannot establish that a particular
older group survived rejection, eviction or failure before that interval began.
Journal reclamation needs evidence tied to its own work, not just healthy counters
or a successful later flush. Legacy callback returns are not explicit commit proof.

## Decision

`enqueue_many_tracked` returns a payload-free `PersistenceTicket` for one packet/
alert group. `SnifferPersistence.persist_batch_tracked` reuses the existing history
record builder and redaction boundary. Normal `persist`/enqueue callers keep their
existing batching and return behavior and do not create tickets.

Tracked groups contain 1-256 packet/alert events. Other categories, including flow
references, are rejected; they cannot lose a ticket through view coalescing. The
existing queue carries the group and handle. No thread, global ticket registry,
runtime file, schema or durable receipt ledger is added.

The worker writes a tracked group as one write unit using the existing retry
policy. It does not split it into per-category buffers or coalesce it with other
groups. Earlier ordinary buffered records need not commit first; this is a receipt
for this group, not a global FIFO storage fence. This mode is for grouped writes,
not an automatic per-packet disk wait. With batching disabled, it deliberately
uses the configured synchronous path before returning, just like legacy writes.

`PersistenceWriteOutcome.confirmed_types` explicitly identifies complete categories
confirmed by an adapter. The writer validates that these categories occur in the
batch and their event counts do not exceed accounted writes. SQLite central history
reports packet/alert confirmation only for its explicit `committed` result. Legacy
returns and typed counts without category confirmation cannot certify tickets.
Flow callback return semantics remain unchanged and do not certify tracked history.

## Results And Ownership

The handle publishes an immutable snapshot with only status and event count:

- `pending`: queued, writing or retrying; timeout observes this without cancelling.
- `committed`: every category in this group explicitly confirmed by the adapter.
- `skipped`: intentional skip; not commit proof or a storage fault by itself.
- `unconfirmed`: a callback returned without sufficient explicit confirmation.
- `failed`: bounded attempts failed or an invalid outcome was reported.
- `dropped`/`rejected`: this group's actual overflow outcome.
- `unavailable`: async worker is already closed/unavailable at admission check.

The first terminal result is stable. A later successful flush or unrelated write
cannot turn a failed handle into success. Wait defaults to a nonblocking snapshot;
callers own references and should use bounded waits off UI/capture threads. An
unexpected worker/process death, including an admission/shutdown race, may leave
a handle pending: that is never permission to reclaim a journal batch.

Handles are process-local observations of trusted adapter reports, not independent
authentication, fsync or exactly-once certificates. They are not serialized into
history rows, public event envelopes or network output.

## Verification And Remaining Work

Tests cover blocked writes, timeout without cancellation, retry before completion,
all overflow policies, legacy/incomplete confirmation, invalid sizes/outcomes,
closed workers, redaction, real SQLite packet/alert commit and transaction rollback.
A failed receipt remains failed even when a later flush returns true.

Normal Capture does not call this opt-in API yet. Journal acknowledgement still
follows its existing callback rule. Before connecting it, define bounded pending
batch windows, disabled-history policy and restart-safe alert identities; measure
grouped-mode throughput and crash/replay behavior. In particular, replaying a failed
or unconfirmed group can duplicate alerts even though packet occurrences have keys.
This change does not claim to resolve that gap or production packet loss.
