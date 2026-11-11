"""Bounded, payload-free completion handles; no threads, files or global registry."""
from dataclasses import dataclass
import threading
from typing import Literal


MAX_TRACKED_GROUP_EVENTS = 256
ReceiptStatus = Literal['pending', 'committed', 'failed', 'skipped', 'dropped',
                        'rejected', 'unconfirmed', 'unavailable']


@dataclass(frozen=True, slots=True)
class PersistenceGroupReceipt:
    status: ReceiptStatus
    events: int

    @property
    def succeeded(self) -> bool:
        return self.status == 'committed'


class PersistenceTicket:
    """One group, one terminal result. Timeout observes pending; it cancels nothing.

    Committed means the configured adapter explicitly confirmed this group's
    categories. It is not an independent fsync or exactly-once certificate.
    """

    def __init__(self, events: int):
        if type(events) is not int or not 1 <= events <= MAX_TRACKED_GROUP_EVENTS:
            raise ValueError('Tracked group size is outside the supported bound')
        self._events = events
        self._status: ReceiptStatus = 'pending'
        self._lock = threading.Lock()
        self._done = threading.Event()

    def wait(self, timeout_sec: float | None = 0.0) -> PersistenceGroupReceipt:
        self._done.wait(None if timeout_sec is None else max(0.0, timeout_sec))
        with self._lock:
            return PersistenceGroupReceipt(self._status, self._events)

    def _resolve(self, status: ReceiptStatus) -> None:
        if status == 'pending':
            raise ValueError('Pending is not a terminal receipt')
        with self._lock:
            if self._status != 'pending':
                return
            self._status = status
            self._done.set()
