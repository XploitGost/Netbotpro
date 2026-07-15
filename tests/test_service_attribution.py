import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app.services.batch_persistence import BatchPersistenceWriter
from backend.app.services.event_aggregator import EventAggregator
from backend.app.services.live_ring_buffer import DEFAULT_CAPACITIES, LiveRingBuffer
from backend.app.services.monitoring_service import build_monitoring_metrics
from backend.app.services.service_attribution import (
    DEFAULT_REGISTRY_PATH,
    ServiceAttributionEngine,
    attribute_service,
)
from core.flow_engine import FlowEngine


class ServiceAttributionTests(unittest.TestCase):
    def setUp(self):
        self.engine = ServiceAttributionEngine(DEFAULT_REGISTRY_PATH)

    def result(self, **packet):
        defaults = {
            "process_name": "chrome.exe",
            "src": "10.0.0.5",
            "dst": "198.51.100.20",
            "sport": 52000,
            "dport": 443,
            "app_protocol": "TLS",
        }
        defaults.update(packet)
        return self.engine.attribute(defaults).to_dict()

    def test_loads_local_registry(self):
        metrics = self.engine.metrics()
        self.assertGreaterEqual(metrics["registry_size"], 20)
        self.assertEqual(metrics["health"], "healthy")

    def test_invalid_registry_degrades_without_crashing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text("{not-json", encoding="utf-8")
            engine = ServiceAttributionEngine(path)
            result = engine.attribute({"dport": 443}).to_dict()

        self.assertTrue(result["is_unknown"])
        self.assertEqual(engine.metrics()["health"], "critical")
        self.assertIn(
            "service_attribution_registry_error",
            engine.metrics()["pressure_reasons"],
        )

    def test_googlevideo_sni_is_youtube_high_confidence(self):
        result = self.result(tls_sni="r1.googlevideo.com")
        self.assertEqual(result["service_name"], "YouTube")
        self.assertEqual(result["attribution_confidence"], "high")
        self.assertIn("tls_sni", result["attribution_sources"])

    def test_youtube_domain_is_high_confidence(self):
        result = self.result(tls_sni="youtube.com")
        self.assertEqual(result["service_name"], "YouTube")
        self.assertGreaterEqual(result["confidence_score"], 80)

    def test_telegram_and_github_browser_destinations(self):
        telegram = self.result(http_host="web.telegram.org")
        github = self.result(http_host="github.com")
        self.assertEqual(telegram["service_name"], "Telegram Web")
        self.assertEqual(github["service_name"], "GitHub")
        self.assertEqual(github["service_category"], "Developer Platform")

    def test_discord_cdn_domain_is_attributed_conservatively(self):
        result = self.result(tls_sni="cdn.discordapp.com")
        self.assertEqual(result["service_name"], "Discord")
        self.assertTrue(result["is_cdn"])

    def test_dns_only_match_is_medium_confidence(self):
        result = self.result(dns_qname="pypi.org", app_protocol="DNS", dport=53)
        self.assertEqual(result["service_name"], "PyPI")
        self.assertEqual(result["attribution_confidence"], "medium")

    def test_recent_dns_answer_correlates_destination_ip(self):
        self.engine.attribute(
            {
                "dns_qname": "r2.googlevideo.com",
                "dns_answer_ips": ["203.0.113.44"],
                "ts": "2026-07-15T10:00:00Z",
                "dport": 53,
            }
        )
        result = self.engine.attribute(
            {
                "process_name": "chrome.exe",
                "dst": "203.0.113.44",
                "dport": 443,
                "ts": "2026-07-15T10:01:00Z",
            }
        ).to_dict()
        self.assertEqual(result["service_name"], "YouTube")
        self.assertIn("dns", result["attribution_sources"])

    def test_dns_correlation_prefers_closest_observation(self):
        for domain, timestamp in (
            ("github.com", "2026-07-15T10:00:00Z"),
            ("pypi.org", "2026-07-15T10:04:30Z"),
        ):
            self.engine.attribute(
                {
                    "dns_qname": domain,
                    "dns_answer_ip": "203.0.113.45",
                    "ts": timestamp,
                    "dport": 53,
                }
            )
        result = self.engine.attribute(
            {
                "dst": "203.0.113.45",
                "dport": 443,
                "ts": "2026-07-15T10:05:00Z",
            }
        ).to_dict()
        self.assertEqual(result["service_name"], "PyPI")

    def test_visible_quic_server_name_reuses_safe_sni_matching(self):
        result = self.result(tls_sni="", quic_server_name="googlevideo.com")
        self.assertEqual(result["service_name"], "YouTube")
        self.assertIn("tls_sni", result["attribution_sources"])

    def test_http_host_is_high_confidence(self):
        result = self.result(http_host="github.com", app_protocol="HTTP", dport=80)
        self.assertEqual(result["attribution_confidence"], "high")
        self.assertIn("HTTP Host matched github.com", result["attribution_reasons"])

    def test_conflicting_host_and_sni_reduce_confidence(self):
        result = self.result(http_host="github.com", tls_sni="googlevideo.com")
        self.assertEqual(result["service_name"], "GitHub")
        self.assertEqual(result["attribution_confidence"], "medium")
        self.assertTrue(
            any("Conflicting" in reason for reason in result["attribution_reasons"])
        )

    def test_cloudflare_only_evidence_is_cdn_only_low_confidence(self):
        result = self.result(org="Cloudflare, Inc.", tls_sni="")
        self.assertEqual(result["service_name"], "CDN only")
        self.assertEqual(result["attribution_confidence"], "low")
        self.assertTrue(result["is_cdn"])

    def test_browser_process_alone_is_unknown_encrypted(self):
        result = self.result()
        self.assertTrue(result["is_unknown"])
        self.assertEqual(result["service_name"], "Unknown encrypted destination")
        self.assertEqual(result["attribution_confidence"], "low")

    def test_unencrypted_process_only_stays_unknown(self):
        result = self.result(dport=80, app_protocol="TCP")
        self.assertTrue(result["is_unknown"])
        self.assertEqual(result["attribution_confidence"], "unknown")
        self.assertLess(result["confidence_score"], 20)

    def test_malformed_input_does_not_crash(self):
        result = self.engine.attribute(
            {"dport": {}, "resolved_domains": [None, {"bad": "value"}]}
        ).to_dict()
        self.assertTrue(result["is_unknown"])

    def test_metrics_count_confidence_unknown_and_latency(self):
        self.result(flow_id="github-flow", http_host="github.com")
        self.result(
            flow_id="pypi-flow", dns_qname="pypi.org", app_protocol="DNS", dport=53
        )
        self.result(flow_id="unknown-flow")
        metrics = self.engine.metrics()
        self.assertEqual(metrics["attributed_flows_total"], 2)
        self.assertEqual(metrics["unknown_flows_total"], 1)
        self.assertEqual(metrics["high_confidence_total"], 1)
        self.assertEqual(metrics["medium_confidence_total"], 1)
        self.assertEqual(metrics["low_confidence_total"], 1)
        self.assertGreaterEqual(metrics["avg_attribution_latency_ms"], 0)

    def test_metrics_count_unique_flows_and_replace_improved_evidence(self):
        self.result(flow_id="same-flow")
        self.result(flow_id="same-flow")
        self.assertEqual(self.engine.metrics()["unknown_flows_total"], 1)

        self.result(flow_id="same-flow", tls_sni="github.com")
        metrics = self.engine.metrics()
        self.assertEqual(metrics["unknown_flows_total"], 0)
        self.assertEqual(metrics["attributed_flows_total"], 1)

    def test_repeated_enrichment_failures_make_health_critical(self):
        with patch.object(self.engine, "_attribute", side_effect=RuntimeError):
            for index in range(25):
                self.engine.attribute({"flow_id": f"failure-{index}", "dport": 443})

        metrics = self.engine.metrics()
        self.assertEqual(metrics["attribution_errors_total"], 25)
        self.assertEqual(metrics["health"], "critical")

    def test_sensitive_values_are_redacted(self):
        result = self.result(
            tls_sni="",
            org="Authorization: Bearer raw-service-secret",
        )
        self.assertNotIn("raw-service-secret", json.dumps(result))

    def test_legacy_wrapper_remains_compatible(self):
        result = attribute_service(
            {"process_name": "chrome.exe", "tls_sni": "googlevideo.com", "dport": 443}
        )
        self.assertEqual(result["service_confidence"], "high")
        self.assertEqual(result["service_sources"][0], "tls_sni")

    def test_flow_ring_event_and_persistence_keep_redacted_attribution(self):
        packet = {
            "id": "pkt-1",
            "src": "10.0.0.5",
            "dst": "198.51.100.20",
            "sport": 52000,
            "dport": 443,
            "proto": "TCP",
            "length": 120,
            "tls_sni": "github.com",
            "process_name": "chrome.exe",
        }
        self.engine.enrich(packet)
        flow = FlowEngine().ingest(packet)
        self.assertEqual(flow["service_attribution"]["service_name"], "GitHub")

        capacities = {category: 5 for category in DEFAULT_CAPACITIES}
        ring = LiveRingBuffer(capacities=capacities)
        ring.append("flow", flow)
        self.assertEqual(
            ring.query("flow")["items"][0]["payload"]["service_attribution"][
                "service_name"
            ],
            "GitHub",
        )

        emitted = []
        aggregator = EventAggregator(emitted.append, flow_batch_max=1)
        aggregator.publish("flow:update", flow)
        self.assertEqual(
            emitted[0]["updates"][0]["payload"]["service_attribution"]["service_name"],
            "GitHub",
        )
        aggregator.close()

        written = []
        writer = BatchPersistenceWriter(
            lambda grouped: written.extend(grouped.get("flow_record", [])),
            enabled=False,
        )
        secret_flow = dict(flow)
        secret_flow["service_attribution"] = {
            **flow["service_attribution"],
            "secret": "raw-persistence-secret",
        }
        writer.enqueue("flow_record", secret_flow)
        self.assertNotIn("raw-persistence-secret", json.dumps(written))

    def test_monitoring_snapshot_includes_safe_metrics(self):
        self.result(http_host="github.com")
        metrics = build_monitoring_metrics(
            sniffer_state={},
            observability={"service_attribution": self.engine.metrics()},
            flow_summary={},
        )
        self.assertIn("service_attribution", metrics)
        self.assertGreater(metrics["service_attribution"]["registry_size"], 0)
        self.assertNotIn("domain", json.dumps(metrics["service_attribution"]))


if __name__ == "__main__":
    unittest.main()
