"""Persistence operation results, independent of queue and storage implementations."""
from dataclasses import dataclass
from typing import Literal


FlushStatus = Literal['completed', 'synchronous', 'worker_unavailable',
                      'queue_timeout', 'timeout', 'superseded']


@dataclass(frozen=True, slots=True)
class PersistenceFlushReceipt:
    """A local write-behind barrier result, not a crash-atomic storage receipt.

    Historical loss stays visible. Success covers only the observation interval;
    it does not recover previously dropped data or cover later queue admissions.
    """

    status: FlushStatus
    failed_before: int
    failed_after: int
    dropped_before: int
    dropped_after: int

    @property
    def succeeded(self) -> bool:
        return (self.status in {'completed', 'synchronous'}
                and self.failed_after == self.failed_before
                and self.dropped_after == self.dropped_before)
