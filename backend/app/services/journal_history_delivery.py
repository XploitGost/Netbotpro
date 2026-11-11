"""Opt-in one-batch history confirmation before publication and journal ack."""
from typing import Callable

from backend.app.services.packet_delivery import AnalyzedPacket
from backend.app.services.persistence_ticket import PersistenceTicket, MAX_TRACKED_GROUP_EVENTS
from core.alert_identity import valid_alert_event_id
from core.capture.identity import valid_capture_event_id
from core.capture.batch_delivery import BatchCompletionReceipt


MAX_HISTORY_BATCH_PACKETS = 32
HISTORY_COMMIT_TIMEOUT_SEC = 10.0


class JournalHistoryDelivery:
    def __init__(self, analyze: Callable, submit: Callable, publish: Callable,
                 *, timeout_sec: float = HISTORY_COMMIT_TIMEOUT_SEC):
        if (type(timeout_sec) not in (int, float)
                or not 0 < timeout_sec <= HISTORY_COMMIT_TIMEOUT_SEC):
            raise ValueError('History commit wait must be positive and bounded')
        self._analyze = analyze
        self._submit = submit
        self._publish = publish
        self._timeout = timeout_sec

    @staticmethod
    def validate_batch(packets: list[dict]) -> None:
        if not 1 <= len(packets) <= MAX_HISTORY_BATCH_PACKETS:
            raise ValueError('History-confirmed journal batch exceeds its packet bound')
        identities = [valid_capture_event_id(row.get('capture_event_id')) for row in packets]
        if None in identities or len(set(identities)) != len(identities):
            raise ValueError('History-confirmed batches require distinct stable packet identities')

    def analyze(self, packet: dict) -> AnalyzedPacket:
        identity = valid_capture_event_id(packet.get('capture_event_id'))
        if identity is None:
            raise ValueError('History-confirmed packet identity is missing')
        result = self._analyze(packet)
        if not isinstance(result, AnalyzedPacket) or result.packet.get('capture_event_id') != identity:
            raise ValueError('Analysis changed the journal occurrence identity')
        if any(valid_alert_event_id(row.get('alert_event_id')) is None for row in result.alerts):
            raise ValueError('History-confirmed alerts require stable occurrence identities')
        return result

    def complete(self, identifier: int, results: list[AnalyzedPacket]) -> BatchCompletionReceipt:
        if any(not isinstance(result, AnalyzedPacket) for result in results):
            raise ValueError('History completion requires analyzed packet results')
        self.validate_batch([result.packet for result in results])
        alert_ids = [valid_alert_event_id(row.get('alert_event_id'))
                     for result in results for row in result.alerts]
        if None in alert_ids or len(set(alert_ids)) != len(alert_ids):
            raise ValueError('History-confirmed batches require distinct stable alert identities')
        events = sum(1 + len(result.alerts) for result in results)
        if events > MAX_TRACKED_GROUP_EVENTS:
            raise ValueError('History-confirmed batch exceeds its record bound')
        ticket = self._submit([(result.packet, result.alerts) for result in results])
        if not isinstance(ticket, PersistenceTicket):
            raise RuntimeError('History batch did not return a tracked write ticket')
        receipt = ticket.wait(self._timeout)
        if not receipt.succeeded or receipt.events != events:
            raise RuntimeError(f'History batch is not confirmed: {receipt.status}')
        for result in results:
            self._publish(result)
        return BatchCompletionReceipt(identifier, len(results))
