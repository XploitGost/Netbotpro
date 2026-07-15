from __future__ import annotations

from typing import Any

from backend.app.services.event_bus import EventBus


class SnifferEventPublisher:
    def __init__(self, event_bus: EventBus) -> None:
        self._event_bus = event_bus

    def publish_packet(self, packet: dict[str, Any]) -> None:
        self._event_bus.publish("packet:new", packet)

    def publish_alerts(self, alerts: list[dict[str, Any]]) -> None:
        for alert in alerts:
            self._event_bus.publish("alert:new", alert)

    def publish_incidents(self, incidents: list[dict[str, Any]]) -> None:
        for incident in incidents:
            self._event_bus.publish("incident:update", incident)

    def publish_state(self, event_type: str, state: dict[str, Any]) -> None:
        self._event_bus.publish(event_type, state)
