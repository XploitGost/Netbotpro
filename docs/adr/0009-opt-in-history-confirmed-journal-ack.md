# ADR 0009: Opt-in history-confirmed journal acknowledgement

Status: implemented, experimental and disabled by default.

## Decision

`NETBOT_JOURNAL_ACK_MODE=history` connects the tracked history receipts from
ADR 0007 to journal reclamation. It requires `NETBOT_CAPTURE_JOURNAL=1`, a
`ProcessCaptureSession` and enabled history storage. Invalid policy fails before
service workers start; disabled storage fails before Capture starts. The existing
`callback` policy remains the default. No installed desktop configuration changes.

The application bridge `JournalHistoryDelivery` owns this sequence:

1. Validate a journal batch containing 1 to 32 distinct stable packet identities.
2. Analyze each record, retaining its occurrence identity and requiring stable
   occurrence identities for every resulting alert.
3. Submit packets and alerts as one tracked group, at most 256 records.
4. Wait once, at most 10 seconds, for that group's explicit committed receipt.
5. Publish through the existing delivery ports without enqueuing history again.
6. Return a completion receipt bound to the batch identifier and callback count.
   Only then may the capture coordinator acknowledge the journal batch.

Only one batch is awaiting confirmation in this synchronous journal consumer.
No global flush, new worker, unbounded result catalog or receipt ledger is added.
The capture layer knows a completion port and typed receipt, not SQLite or the
application bridge. The normal path does not retain callback results.

## Failure And Replay

Missing/duplicate identities, unknown alert provenance, an oversized group,
analysis failure, queue rejection/drop, skip, unavailable writer, unconfirmed
adapter return, timeout, publication failure or mismatched completion receipt
prevents acknowledgement. Existing process-session failure handling stops intake
and retains the journal rather than silently falling back to callback policy.

A timeout observes a still-pending ticket; it does not cancel a queued write.
That write can commit later. A crash or publication failure after commit can also
leave the batch retained. Replaying the same identified packet/alert occurrences
does not duplicate retained history rows (ADRs 0005 and 0008). Retention removes
that protection when rows are deleted; this is not a permanent deduplication log.

## Guarantee And Non-Guarantees

The receipt confirms the packet/alert history adapter's commit return, including
duplicate-only commits with zero new rows. It does not prove power-loss fsync
durability: SQLite's existing WAL/synchronous settings are unchanged.

Analysis is stateful and can already mutate flow/detector/endpoint/incident state
or perform configured side effects before history confirmation. These mutations,
flow persistence, read models and event delivery are not one transaction with
history. Publication can partially succeed and can repeat on replay. This is not
exactly-once processing, state checkpointing or a cross-database transaction.

`ipc_delivered` still counts completed analysis callbacks, not committed history.
`journal_acknowledged_records` counts records after completion and journal ack.
Status exposes `journal_completion_required`; application observability exposes
`analysis_delivery.mode=journal_history`, the policy, history scope and batch cap.

## Verification And Promotion

Tests cover default-path compatibility, commit/publication/ack order, every
negative ticket status, invalid identity/receipt/bounds, no duplicate enqueue,
strict error propagation, real SQLite writes, encrypted Windows process capture
of 40 records in two groups, and commit-before-ack replay without duplicate rows.

CI/synthetic tests do not establish live throughput, driver loss or long-session
stability. Keep this policy opt-in until real-traffic soak, route-change, shutdown
and storage-failure tests establish acceptable latency and bounded journal growth.
No Rust migration or performance improvement is claimed by this decision.
