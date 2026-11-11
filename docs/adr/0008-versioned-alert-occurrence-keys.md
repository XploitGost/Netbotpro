# ADR 0008: Versioned alert occurrence keys

Status: retained history-row replay protection for identified detections only.

## Context

Packet occurrence keys do not prevent duplicate alert rows when a journal entry
is analyzed again. Process-local alert counters, display titles and mutable score/
detail fields cannot identify a detection occurrence safely. Unknown provenance
must not be guessed from an alert title or silently collapsed.

## Decision

Built-in signature, ML and application detectors report namespaced rule keys and
an explicit identity-contract version. Custom rule keys hash their detector
family, list position and effective configuration (name, source, port, window,
threshold). Identical custom rules at different positions stay distinct. Editing
or reordering custom rules can change their keys, conservatively producing new
history rows rather than merging different configurations.

For a valid journal packet occurrence, the detection pipeline derives a versioned
SHA-256 key from the packet key, rule key, version and ordinal within that rule's
outputs for this packet. Ordinals are assigned before service-level coalescing;
unrelated rules do not renumber them. The hash is not over packet content, score,
detail, correlation counts or destination attribution. Similar independent packets
have different keys. Syntax checks are not provenance/authentication certificates.

No key is synthesized for missing/invalid packet or rule provenance. Such alerts
remain legacy records without replay deduplication. Built-in version `1` identifies
the rule occurrence contract, not ML model weights or reproducible detector state.
Rule owners must version identity/meaning changes deliberately; this is not a new
analysis-run/version management system.

History adds nullable `alert_event_id`, `detection_rule_key` and
`detection_rule_version` columns. A partial unique index protects only non-null
occurrence keys. Targeted conflict handling retains the first stored observation;
it does not overwrite it when scores/details change on reevaluation. Other SQL
constraint failures still roll back the packet/alert transaction. Actual inserted
row counts distinguish replay from a new alert. Display/live alert IDs and API
selection routes are unchanged; the durable key is separate.

## Migration And Limits

Old records remain null-keyed; no old alert is deleted, renamed or deduplicated.
Index creation scans history and consumes space per retained identified alert;
large-history migration/throughput still need measurement before deployment.
Retention deletion removes replay protection for that row. There are no permanent
tombstones, new receipt files or global identity caches.

Stateful detectors or a changed ML model can emit a different set of alerts after
restart. These keys do not restore omitted detections, checkpoint analysis state,
deduplicate live views/incident/flow side effects or provide exactly-once analysis.
Deliberate reanalysis of the same event/rule/version retains the first history row;
a separate version/run policy is needed to keep multiple intentional evaluations.

Normal Capture still uses its existing journal acknowledgement rule. The tracked
history API remains opt-in. Identified alert rows are another prerequisite, not
completion of durable batch acknowledgement or production packet-loss recovery.

## Verification

Tests cover version/rule/slot/event separation, pre-coalescing assignment, mutable
context exclusion, unknown provenance, custom rule scoping, old-schema migration,
invalid-key preservation, redaction, first-write retention and unrelated constraint
rollback. Real SQLite and Windows DPAPI reopen tests replay a modeled history-
commit-before-journal-ack window without new packet or identified alert rows.
This is controlled reopen/replay validation, not abrupt power-loss testing.
