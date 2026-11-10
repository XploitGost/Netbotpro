"""SQLite history adapter results, independent of capture and application services."""
from typing import Literal, TypedDict


class HistoryWriteResult(TypedDict):
    status: Literal['committed', 'disabled', 'unavailable']
    retries: int
    packets_inserted: int
    alerts_inserted: int
