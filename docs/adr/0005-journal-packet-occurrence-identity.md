# ADR 0005: Stable journal packet occurrence identity

Status: retained packet-row replay protection, not exactly-once analysis or storage.

## Context

Process-local `mem-pkt` counters restart and cannot identify a journal occurrence
after recovery. Content hashes would incorrectly collapse genuinely repeated
packets. Legacy capture IDs are not unique across sessions and must not receive
a retroactive uniqueness constraint.

## Decision

Each journal database stores one random namespace row, shared by its readers and
writer. A decoded occurrence receives `capture_event_id` in the versioned form
`cap-v1:<namespace>:<batch-id>:<offset>`. SQLite's existing AUTOINCREMENT batch ID
and the packet's position identify the occurrence. Reopening, renaming or replaying
the same database preserves the key; a newly created database has a new namespace.
Copies represent the same origin, not independent writable journal forks.

Assignment occurs on the owned decoded rows, not on caller dictionaries or the
producer's hot callback. It also gives old encrypted batches stable keys once the
journal is upgraded. A malformed namespace fails rather than silently changing
identities. Payload encryption and journal acknowledgement policy are unchanged.
The namespace is not sensitive traffic and is not an authentication credential.

Analysis uses a recognized occurrence key as its default packet ID. Existing
explicit IDs are preserved. The history adapter carries the occurrence key into
a new nullable packet column with a partial unique index for non-null keys.
Malformed/unversioned values become null at this storage boundary. Syntax checking
does not certify trust, redaction or provenance. Existing output redaction remains.

Only a conflict on that key suppresses insertion of that packet row, retaining its
first stored version. Other constraint failures still propagate and roll back the
packet/alert transaction. Independent alerts are not suppressed. The storage result
reports actual inserted row counts so replay is not counted as newly stored packets.
Disabled/unavailable storage reports zero inserted rows, not a durability receipt.

## Migration And Bounds

Migration adds a nullable column and index; old rows retain null occurrence keys
and are neither deleted nor deduplicated. Old `capture_id` duplicates remain legal.
Already-stored legacy rows cannot be linked retroactively to upgraded journal rows.
Index construction scans the existing table; its time on large production histories
must be checked before deployment. This change has not migrated the installed app.

There is one namespace row per journal, not a growing receipt ledger. The history
column and index consume space per retained packet and follow packet retention.
If a row is deleted by retention, replay may insert it again. There are no permanent
tombstones and no claim of zero overhead or proven capture-throughput improvement.

## Remaining Work And Verification

Journal acknowledgement still follows callbacks, which may only enqueue history.
Thus data can still be lost after acknowledgement and before a durable write.
Alert identities and analysis/flow side effects are not made idempotent here.
Crash-atomicity, power-loss recovery and end-to-end exactly-once processing remain
open. Stable adapter outcomes and alert/flow identity contracts are still needed.

Tests cover reopened histories, migration with old duplicates, unrelated constraint
rollback, independent alerts, two simultaneous journal handles, distinct namespaces,
identical packet occurrences, preserved IDs through analysis/redaction and the
modeled restart window after history commit but before journal acknowledgement.
This is reopen/replay validation, not an abrupt power-loss test.
