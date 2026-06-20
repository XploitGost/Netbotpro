from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass
from typing import Any


VALID_OVERFLOW_POLICIES = {"drop_oldest", "drop_newest"}


@dataclass(frozen=True)
class PacketQueueItem:
    packet: dict[str, Any]


class BoundedPacketQueue:
    """Bounded packet intake queue with explicit overflow accounting."""

    def __init__(self, max_size: int = 2000, overflow_policy: str = "drop_oldest") -> None:
        self._queue: queue.Queue[PacketQueueItem] = queue.Queue(maxsize=max(1, int(max_size)))
        self._overflow_policy = (
            overflow_policy if overflow_policy in VALID_OVERFLOW_POLICIES else "drop_oldest"
        )
        self._lock = threading.Lock()
        self._accepted_packets = 0
        self._dropped_packets = 0
        self._dropped_oldest = 0
        self._dropped_newest = 0
        self._queue_high_water_mark = 0

    @property
    def overflow_policy(self) -> str:
        return self._overflow_policy

    def put(self, packet: dict[str, Any]) -> bool:
        item = PacketQueueItem(packet=dict(packet))
        try:
            self._queue.put_nowait(item)
            self._record_accepted()
            return True
        except queue.Full:
            return self._handle_overflow(item)

    def get(self, timeout: float | None = None) -> PacketQueueItem:
        return self._queue.get(timeout=timeout)

    def task_done(self) -> None:
        self._queue.task_done()

    def empty(self) -> bool:
        return self._queue.empty()

    def qsize(self) -> int:
        return self._queue.qsize()

    def clear(self) -> int:
        removed = 0
        while True:
            try:
                self._queue.get_nowait()
                self._queue.task_done()
                removed += 1
            except queue.Empty:
                break
        return removed

    def wait_until_drained(self, timeout_sec: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout_sec)
        while time.monotonic() < deadline:
            if self.unfinished_tasks() == 0:
                return True
            time.sleep(0.01)
        return self.unfinished_tasks() == 0

    def unfinished_tasks(self) -> int:
        return int(getattr(self._queue, "unfinished_tasks", 0))

    def stats(self) -> dict[str, int | str]:
        with self._lock:
            return {
                "max_size": self._queue.maxsize,
                "queue_size": self._queue.qsize(),
                "queue_high_water_mark": self._queue_high_water_mark,
                "accepted_packets": self._accepted_packets,
                "dropped_packets": self._dropped_packets,
                "dropped_oldest": self._dropped_oldest,
                "dropped_newest": self._dropped_newest,
                "overflow_policy": self._overflow_policy,
            }

    def _record_accepted(self) -> None:
        with self._lock:
            self._accepted_packets += 1
            self._queue_high_water_mark = max(
                self._queue_high_water_mark,
                self._queue.qsize(),
            )

    def _handle_overflow(self, item: PacketQueueItem) -> bool:
        if self._overflow_policy == "drop_newest":
            with self._lock:
                self._dropped_packets += 1
                self._dropped_newest += 1
                self._queue_high_water_mark = max(
                    self._queue_high_water_mark,
                    self._queue.qsize(),
                )
            return False

        try:
            self._queue.get_nowait()
            self._queue.task_done()
        except queue.Empty:
            pass
        with self._lock:
            self._dropped_packets += 1
            self._dropped_oldest += 1

        try:
            self._queue.put_nowait(item)
            self._record_accepted()
            return True
        except queue.Full:
            with self._lock:
                self._dropped_packets += 1
                self._dropped_newest += 1
                self._queue_high_water_mark = max(
                    self._queue_high_water_mark,
                    self._queue.qsize(),
                )
            return False


__all__ = ["BoundedPacketQueue", "PacketQueueItem"]
