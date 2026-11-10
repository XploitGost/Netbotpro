"""Persistence operation results, independent of queue and storage implementations."""
from dataclasses import dataclass
from typing import Literal


FlushStatus = Literal['completed', 'synchronous', 'worker_unavailable',
                      'queue_timeout', 'timeout', 'superseded']


class HistoryStorageUnavailable(RuntimeError):
    """Enabled history has no connection; a successful write cannot be inferred."""


@dataclass(frozen=True, slots=True)
class PersistenceWriteOutcome:
    """Adapter-confirmed processing versus intentional skips, not inserted row counts."""

    written_events: int
    skipped_events: int = 0
    storage_retries: int = 0

    def __post_init__(self) -> None:
        for value in (self.written_events, self.skipped_events, self.storage_retries):
            if type(value) is not int or value < 0:
                raise ValueError('Write outcome counts must be nonnegative integers')


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
    skipped_before: int = 0
    skipped_after: int = 0

    @property
    def succeeded(self) -> bool:
        return (self.status in {'completed', 'synchronous'}
                and self.failed_after == self.failed_before
                and self.dropped_after == self.dropped_before
                and self.skipped_after == self.skipped_before)
