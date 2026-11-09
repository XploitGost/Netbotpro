import ast
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
import unittest
from unittest.mock import Mock

from backend.app.services.packet_delivery import AnalyzedPacket, DeliveryPorts, PacketDelivery


def result(flow=True):
    return AnalyzedPacket(
        packet={"id": "packet-1", "timestamp": "2026-11-09T12:00:00Z"},
        flow={"flow_id": "flow-1", "timeline": list(range(30)),
              "related_alert_ids": list(range(25))} if flow else None,
        flow_key="flow-1", alerts=[{"id": "alert-1", "ts": "alert-time"}],
        expert_items=[{"id": "expert-1", "last_seen": "expert-time"}],
        incidents=[{"incident_id": "incident-1", "last_seen": "incident-time"}],
    )


def recording_ports(calls, fail_at=None):
    def recorder(name):
        def invoke(*args, **kwargs):
            tag = name + ":" + args[0] if name.startswith("append_") else name
            calls.append((tag, args, kwargs))
            if tag == fail_at:
                raise OSError("destination unavailable")
        return invoke
    return DeliveryPorts(**{field.name: recorder(field.name) for field in fields(DeliveryPorts)})


ORDER = ["add_packet", "add_alerts", "append_view:packet", "submit_flow_view",
         "append_view:alert", "append_view:expert_info", "append_incident_view:incident",
         "persist_packet", "persist_flow", "publish_packet", "publish_alerts", "publish_incidents"]


class PacketDeliveryTests(unittest.TestCase):
    def test_service_handoff_is_once_and_failed_analysis_never_delivers(self):
        from backend.app.services.sniffer_service import SnifferService
        service = object.__new__(SnifferService)
        item = result()
        service._analyze_packet = Mock(return_value=item)
        service._packet_delivery = Mock()
        source = {"id": "packet-1"}
        self.assertIsNone(service._process_packet(source))
        service._analyze_packet.assert_called_once_with(source)
        service._packet_delivery.deliver.assert_called_once_with(item)
        service._analyze_packet.side_effect = RuntimeError("analysis failed")
        service._packet_delivery.reset_mock()
        with self.assertRaisesRegex(RuntimeError, "analysis failed"):
            service._process_packet(source)
        service._packet_delivery.deliver.assert_not_called()

    def test_legacy_order_payloads_and_timestamps_are_preserved(self):
        calls = []
        item = result()
        PacketDelivery(recording_ports(calls)).deliver(item)
        self.assertEqual([name for name, _, _ in calls], ORDER)
        by_name = {name: (args, kwargs) for name, args, kwargs in calls}
        self.assertIs(by_name["persist_packet"][0][0], item.packet)
        self.assertIs(by_name["persist_packet"][0][1], item.alerts)
        self.assertIs(by_name["persist_flow"][0][0], item.flow)
        for name, timestamp, source in (
            ("append_view:packet", item.packet["timestamp"], "live_capture"),
            ("append_view:alert", "alert-time", "detection_engine"),
            ("append_view:expert_info", "expert-time", "expert_info"),
            ("append_incident_view:incident", "incident-time", "incident_correlation"),
        ):
            self.assertEqual(by_name[name][1], dict(timestamp=timestamp, source=source,
                                                   flow_key="flow-1", return_record=False))

    def test_optional_flow_projection_does_not_truncate_analysis_or_persistence(self):
        calls = []
        item = result()
        item.flow.update(timeline_total=100, timeline_truncated=True)
        before = deepcopy(item.flow)
        PacketDelivery(recording_ports(calls)).deliver(item)
        view = next(args[0] for name, args, _ in calls if name == "submit_flow_view")
        self.assertEqual(view["timeline"], list(range(10, 30)))
        self.assertEqual(view["timeline_total"], 100)
        self.assertTrue(view["timeline_truncated"])
        self.assertEqual(view["related_alert_ids"], list(range(5, 25)))
        self.assertEqual(view["related_alert_ids_total"], 25)
        self.assertEqual(item.flow, before)
        self.assertIsNot(view, item.flow)

    def test_none_flow_keeps_packet_alert_and_event_paths(self):
        calls = []
        PacketDelivery(recording_ports(calls)).deliver(result(flow=False))
        self.assertEqual([name for name, _, _ in calls],
                         [name for name in ORDER if name not in {"submit_flow_view", "persist_flow"}])

    def test_each_destination_failure_propagates_without_later_delivery_or_retry(self):
        for index, failing in enumerate(ORDER):
            with self.subTest(destination=failing):
                calls = []
                with self.assertRaisesRegex(OSError, "destination unavailable"):
                    PacketDelivery(recording_ports(calls, fail_at=failing)).deliver(result())
                self.assertEqual([name for name, _, _ in calls], ORDER[:index + 1])

    def test_empty_collections_are_not_invented_or_dropped(self):
        calls = []
        item = replace(result(flow=False), alerts=[], expert_items=[], incidents=[])
        PacketDelivery(recording_ports(calls)).deliver(item)
        self.assertEqual([name for name, _, _ in calls],
                         ["add_packet", "add_alerts", "append_view:packet", "persist_packet",
                          "publish_packet", "publish_alerts", "publish_incidents"])
        self.assertIs(next(args[0] for name, args, _ in calls if name == "publish_alerts"), item.alerts)

    def test_handoff_is_an_owned_envelope_not_a_redaction_certificate(self):
        from backend.app.services.event_bus import EventBus
        from backend.app.services.live_ring_buffer import LiveRingBuffer
        from backend.app.services.sniffer_event_publisher import SnifferEventPublisher
        calls = []
        ring = LiveRingBuffer()
        bus = EventBus()
        queue = bus.subscribe()
        publisher = SnifferEventPublisher(bus)
        item = result()
        item.packet.update(authorization="Bearer fixture-sensitive", payload_hex="raw-private-bytes",
                           nested={"password": "nested-private-value"})
        with self.assertRaises(FrozenInstanceError):
            item.flow_key = "changed"
        ports = replace(recording_ports(calls), append_view=ring.append, append_incident_view=ring.append,
                        publish_packet=publisher.publish_packet, publish_alerts=publisher.publish_alerts,
                        publish_incidents=publisher.publish_incidents)
        try:
            PacketDelivery(ports).deliver(item)
            bus.flush()
            messages = []
            while not queue.empty():
                messages.append(queue.get_nowait())
            public = ring.recent_payloads("packet")
            self.assertEqual(len(public), 1)
            self.assertEqual(public[0]["payload_hex"], "")
            self.assertNotIn("fixture-sensitive", str(public) + str(messages))
            self.assertNotIn("nested-private-value", str(public) + str(messages))
            item.packet["nested"]["password"] = "later-private-change"
            self.assertNotIn("later-private-change", str(ring.recent_payloads("packet")))
        finally:
            bus.close()

    def test_delivery_module_does_not_depend_on_capture_api_or_lifecycle_owner(self):
        path = Path(__file__).resolve().parents[1] / "backend/app/services/packet_delivery.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
            elif isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
        for module in imports:
            self.assertFalse(module.startswith(("fastapi", "core.capture", "backend.app.main",
                                                "backend.app.services.sniffer_service", "threading", "queue")))
