"""Synchronous journal acknowledgement boundary; no capture or storage ownership."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True, slots=True)
class BatchReceipt:
    """Callbacks completed and journal acknowledgement returned, not a storage receipt."""

    identifier: int
    completed_records: int


class BatchDeliveryError(RuntimeError):
    """Payload-free failure context; a completed prefix may already have side effects."""

    def __init__(self, stage: str, completed_records: int, cause: Exception):
        self.stage = stage
        self.completed_records = completed_records
        outcome = 'acknowledgement unconfirmed' if stage == 'acknowledgement' else 'batch retained'
        super().__init__(f'Journal {stage} failed: {type(cause).__name__}; {outcome}')


class JournalBatchDelivery:
    """Acknowledge only after all callbacks return; never retry a partial batch.

    The caller owns lifecycle and counters. Retained batches can replay a completed
    prefix after restart: this is not exactly-once or durable downstream delivery.
    """

    def __init__(self, callback: Callable[[dict[str, Any]], None],
                 acknowledge: Callable[[int], None], *,
                 prepare: Callable[[list[dict[str, Any]]], None] | None = None,
                 on_completed: Callable[[], None]):
        self._callback = callback
        self._acknowledge = acknowledge
        self._prepare = prepare
        self._on_completed = on_completed

    def deliver(self, identifier: int, packets: list[dict[str, Any]]) -> BatchReceipt:
        completed = 0
        stage = 'preparation'
        try:
            if self._prepare is not None:
                self._prepare(packets)
            stage = 'analysis'
            for packet in packets:
                self._callback(packet)
                completed += 1
                self._on_completed()
            stage = 'acknowledgement'
            self._acknowledge(identifier)
        except Exception as exc:
            raise BatchDeliveryError(stage, completed, exc) from exc
        return BatchReceipt(identifier, completed)
