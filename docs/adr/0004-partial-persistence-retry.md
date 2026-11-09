# ADR 0004: Retry-local progress for partial persistence

Status: confirmed-return retry safety, not durable deduplication or crash recovery.

## Context

Central persistence first inserts packets and alerts in one SQLite transaction,
then calls the separate flow database writer. A flow failure previously retried
the entire callback, including the already-successful packet/alert insert. A real
SQLite regression reproduced two packet and alert rows instead of one after a
single temporary flow failure. Flow upsert does not make history inserts idempotent.

## Decision

The generic batch writer accepts an optional `prepare_write` factory. It runs
once per batch retry cycle, after queue-boundary redaction; the returned callable
owns all attempts for that cycle. Existing adapters without this factory retain
their previous callback path. Both asynchronous and synchronous modes use it.

The sniffer prepares a batch-local operation with two completion flags. A history
callback that returned successfully is not repeated if the later flow callback
fails. A flow callback that returned is not repeated if later maintenance fails.
The operation preserves history-before-flow ordering, cached storage retry counts,
existing retry limits/backoff and existing overflow policies. New batches always
receive fresh state; there is no global identity cache or disk receipt ledger.

Packet/alert counters advance when their history callback returns, even if the
flow callback later exhausts its retries. These retain the storage adapter's
return semantics; they are not newly certified durable commit counters. Generic
batch failure counters remain conservative whole-batch failure diagnostics, so a
failed batch can contain history records whose callback already returned.

## Limits

Completion flags live only through this retry cycle. A process crash, a new batch
containing the same data, or journal replay can repeat earlier side effects.
An adapter that commits and then raises is unconfirmed and may still be retried.
An adapter that silently skips writes (including persistence settings changing)
does not become a durable writer because it returned. This change does not alter
those adapter contracts or capture-journal acknowledgement.

The two databases are not one atomic transaction. No schema migration, global
sequence, deduplication key, fsync guarantee or exactly-once claim is introduced.
Before altering acknowledgement, require explicit storage-adapter outcomes,
stable restart-safe event identities and crash-injection/replay tests.

## Verification

Tests reproduce and fix duplicate history rows in real in-memory SQLite, cover
history failure before flow, terminal flow failure, later maintenance failure,
fresh state for each batch and empty categories. Prepared operations are tested
in synchronous and worker modes. Existing redaction, retries, overflow and flush
barrier tests remain compatibility gates.
