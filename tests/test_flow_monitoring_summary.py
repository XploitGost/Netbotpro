from __future__ import annotations

import random
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app.services.flow_service import FlowService
from core.flow_engine import FlowEngine


def packet(index=0, **values):
    return {"id": f"p-{index}", "ts": "2026-11-08T12:00:00+00:00",
            "src": "10.0.0.5", "dst": "8.8.8.8", "sport": 50000 + index,
            "dport": 443, "proto": "TCP", "direction": "OUTGOING",
            "length": 120, **values}


class FlowMonitoringSummaryTests(unittest.TestCase):
    def assert_summary_matches(self, engine):
        full = engine.summary(compact_top=True)
        compact = engine.monitoring_summary()
        self.assertEqual(compact, {key: full[key] for key in compact})
        self.assertEqual(sum(compact["risk_distribution"].values()), compact["total_flows"])

    def test_empty_reset_and_reuse(self):
        engine = FlowEngine()
        self.assert_summary_matches(engine)
        engine.ingest(packet(), live_summary=True)
        self.assert_summary_matches(engine)
        engine.reset()
        self.assert_summary_matches(engine)
        engine.ingest(packet(2), live_summary=True)
        self.assert_summary_matches(engine)

    def test_risk_transitions_in_both_directions_and_same_level(self):
        engine = FlowEngine()
        for level, score in [("low", 0), ("medium", 50), ("high", 80),
                             ("high", 85), ("critical", 100), ("low", 0)]:
            with patch("core.flow_engine.score_flow", return_value={
                "level": level, "score": score, "reasons": []
            }):
                engine.ingest(packet(), live_summary=True)
            self.assertEqual(engine.monitoring_summary()["risk_distribution"], {level: 1})
            self.assert_summary_matches(engine)

    def test_mixed_flow_updates_match_full_recomputation(self):
        engine = FlowEngine()
        randomizer = random.Random(17)
        for index in range(180):
            identity = randomizer.randrange(24)
            mode = index % 3
            values = (dict(direction="OUTGOING"), dict(direction="INCOMING"),
                      dict(direction="", dst="10.0.0.6"),
                      dict(direction="", src="8.8.4.4", dst="8.8.8.8"))[identity % 4]
            alerts = [{"id": f"alert-{index}", "severity": "high"}] if index % 7 == 0 else []
            engine.ingest(packet(identity, **values), alerts,
                          live_summary=mode == 0, compact_snapshot=mode == 1,
                          redact_snapshot=mode == 2)
            self.assert_summary_matches(engine)

    def test_monitoring_does_not_walk_flows_copy_evidence_or_expose_mutable_state(self):
        class NoWalk(dict):
            def values(self):
                raise AssertionError("Monitoring walked all flows")

            def items(self):
                raise AssertionError("Monitoring copied all flows")

            def __iter__(self):
                raise AssertionError("Monitoring iterated all flows")

        engine = FlowEngine()
        engine.ingest(packet(summary="Authorization: Bearer secret"), live_summary=True)
        engine._flows = NoWalk(engine._flows)
        with patch.object(engine, "_public_flow", side_effect=AssertionError("Copied evidence")):
            result = engine.monitoring_summary()
        result["risk_distribution"].clear()
        self.assertEqual(sum(engine.monitoring_summary()["risk_distribution"].values()), 1)
        self.assertNotIn("secret", str(engine.monitoring_summary()))

    def test_concurrent_ingest_poll_and_reset_preserve_consistency(self):
        engine = FlowEngine()
        errors = []
        def ingest():
            try:
                for index in range(160):
                    engine.ingest(packet(index % 16), live_summary=True)
                    if index == 80:
                        engine.reset()
            except BaseException as exc:
                errors.append(exc)
        worker = threading.Thread(target=ingest)
        worker.start()
        while worker.is_alive():
            summary = engine.monitoring_summary()
            self.assertEqual(sum(summary["risk_distribution"].values()), summary["total_flows"])
            self.assertEqual(summary["external_flows"], summary["total_flows"])
            worker.join(.001)
        worker.join()
        self.assertEqual(errors, [])
        self.assert_summary_matches(engine)

    def test_service_and_monitoring_api_do_not_build_full_summary(self):
        from fastapi.testclient import TestClient
        from backend.app.main import app
        from backend.app.security import require_local_token, require_trusted_client

        with tempfile.TemporaryDirectory() as directory:
            service = FlowService(db_path=Path(directory) / "flows.db")
            try:
                service.ingest_for_analysis(packet())
                expected = service.engine.monitoring_summary()
                self.assertEqual(service.monitoring_summary(), expected)
                overrides = dict(app.dependency_overrides)
                app.dependency_overrides[require_trusted_client] = lambda: None
                app.dependency_overrides[require_local_token] = lambda: None
                try:
                    with patch("backend.app.main.flow_service", service), \
                         patch.object(service, "summary", side_effect=AssertionError("Full summary called")), \
                         patch("backend.app.main._observability_snapshot", return_value={}), \
                         patch("backend.app.main.build_monitoring_metrics", side_effect=lambda **kw: kw["flow_summary"]):
                        response = TestClient(app).get("/api/monitoring/metrics")
                    self.assertEqual(response.status_code, 200)
                    result = response.json()
                    self.assertEqual({key: result[key] for key in expected}, expected)
                finally:
                    app.dependency_overrides.clear()
                    app.dependency_overrides.update(overrides)
            finally:
                service.close()


if __name__ == "__main__":
    unittest.main()
