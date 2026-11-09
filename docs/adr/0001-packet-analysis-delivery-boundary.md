# ADR 0001: Analysis-to-delivery boundary

Status: first source refactor, not the completed architecture migration.

## Context

`SnifferService._process_packet` previously mixed analysis with dashboard state,
ring writes, flow-view coalescing, persistence enqueue and event publication.
This made dependency/ordering changes difficult to test without constructing a
capture/lifecycle service. Profiling also found repeated copying/redaction, but
this ADR does not justify removing any privacy boundary or claim a speed gain.

## Decision

Analysis returns an `AnalyzedPacket` envelope. `PacketDelivery` consumes it through
explicit `DeliveryPorts`. The service remains the composition/lifecycle owner and
adapts current state, ring, flow-view, persistence and publisher implementations.
Detection, capture providers and REST/WebSocket implementations are not imported
by the delivery coordinator.

The envelope is frozen only at its field bindings; nested rows are mutable.
It represents a single-owner handoff, not a deeply immutable object, sanitized
payload or trusted-token bypass. Analysis must not mutate rows after handoff.
Existing retaining/asynchronous destinations remain responsible for detachment
and redaction. Their implementations and policies are unchanged in this slice.

Delivery remains synchronous and in the previous order:

1. Dashboard packet/alert state.
2. Packet ring view, optional compact flow view, alert/expert/incident views.
3. Packet/alert persistence enqueue and configured flow persistence enqueue.
4. Packet, alert and incident event publication.

Exceptions still propagate. No new queue, background worker, retry, drop policy
or acknowledgement is introduced. A return from delivery is **not** a durable
commit receipt. Existing ports that internally handle errors keep that behavior.
Partial side effects on failure are not made transactional by this refactor.

## Verification

Tests cover destination ordering, timestamps/payload identity, compact versus
complete flow views, absent flow/empty collections, every destination exception,
real ring/event privacy boundaries and forbidden cross-layer imports. Existing
service, journal error, view coalescing, persistence and lifecycle tests remain
the integration gates. Replay/soak validation is still required before promotion.

## Next Slices

Separate capture batch sequencing/acknowledgement from lifecycle control. Then
define durable delivery receipts and privacy-safe owned read models before
optimizing duplicate copies or considering a native analysis core.
