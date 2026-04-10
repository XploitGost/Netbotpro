from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timezone
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[asyncio.Queue[dict[str, Any]], asyncio.AbstractEventLoop | None] = {}
        self._lock = threading.Lock()
        self._dropped_subscribers = 0
        self._dropped_messages = 0
        self._published_messages = 0

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        with self._lock:
            self._subscribers[queue] = loop
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        with self._lock:
            self._subscribers.pop(queue, None)

    def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        message = {
            "version": 1,
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        with self._lock:
            subscribers = list(self._subscribers.items())
            self._published_messages += 1
        for queue, loop in subscribers:
            if loop is not None and loop.is_running():
                try:
                    loop.call_soon_threadsafe(self._safe_put, queue, message)
                except RuntimeError:
                    with self._lock:
                        self._subscribers.pop(queue, None)
                        self._dropped_subscribers += 1
            else:
                self._safe_put(queue, message)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "subscribers": len(self._subscribers),
                "dropped_subscribers": self._dropped_subscribers,
                "dropped_messages": self._dropped_messages,
                "published_messages": self._published_messages,
            }

    def _safe_put(self, queue: asyncio.Queue[dict[str, Any]], message: dict[str, Any]) -> None:
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            with self._lock:
                self._subscribers.pop(queue, None)
                self._dropped_subscribers += 1
                self._dropped_messages += 1
