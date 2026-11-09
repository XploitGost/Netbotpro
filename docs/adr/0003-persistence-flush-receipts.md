# ADR 0003: Explicit write-behind flush results

Status: local persistence barrier correctness; not end-to-end durable delivery.

## Context

The writer previously returned the completion event's boolean. Overflow eviction
of a flush command signalled that event just like a successful flush. Terminal
write errors were counted internally but also left the event signalled. Both
cases could make the writer's public `flush()` report success without the writes
being completed successfully. The sniffer wrapper checked new failures, but did
not distinguish eviction or newly dropped data.

## Decision

`PersistenceFlushReceipt` is a storage/queue-independent result contract.
`BatchPersistenceWriter.flush_result()` returns it; the compatible boolean
`flush()` and the sniffer adapter use its `succeeded` property.

- `completed`: the FIFO command ran and forced preceding buffered work to attempt
  writing. This status alone does not certify successful storage.
- `synchronous`: batching is disabled; this call has no queued barrier to wait for.
- `worker_unavailable`, `queue_timeout`, `timeout`, `superseded`: the barrier did
  not establish completion and must not report success.

The receipt carries cumulative failed/dropped event counts before and after the
operation. Success requires completion/synchronous status and no observed increase
in either count. Historical failures remain visible without making all future
clean flushes fail permanently. Concurrent losses, including those for newer
admissions, may conservatively make a barrier fail. The receipt is an observation
interval, not per-record tracking or a global atomic accounting snapshot.

Queue admission and completion share one monotonic timeout budget. Timeout does
not cancel admitted work: the worker can finish it later. Evicted commands wake
their waiters with `superseded`, not `completed`. Overflow and retry policies for
data records remain unchanged. The hot enqueue path gets no new per-record receipt,
copy, lock or queue scan.

## Limits And Verification

Returning successfully still depends on the storage callback's contract. It does
not prove crash-atomicity, fsync, an all-category transaction or downstream exactly-
once writes. It does not restore earlier dropped events. Capture-journal
acknowledgement remains a separate contract and is not delayed by this barrier.

Regression tests reproduce both false-success bugs, then cover new losses during
a blocked write, timeouts, unavailable workers, synchronous mode, visible historical
failure and the sniffer adapter. Existing redaction, batching, overflow, bounded
retry, coalescing and graceful-exit tests remain compatibility gates.

Next: define stable event identities and storage-adapter commit receipts before
changing journal acknowledgement or retry semantics across partially committed
packet/alert/flow writes.
