import json
import re
import unittest
from pathlib import Path

from agent.agent_identity import AGENT_VERSION
from backend.app.main import app

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET_VERSION = "0.2.0"


class ReleaseReadinessTests(unittest.TestCase):
    def _read(self, relative_path: str) -> str:
        return (REPO_ROOT / relative_path).read_text(encoding="utf-8")

    def _json(self, relative_path: str) -> dict:
        return json.loads(self._read(relative_path))

    def test_version_consistency(self):
        frontend = self._json("frontend/package.json")
        frontend_lock = self._json("frontend/package-lock.json")
        electron = self._json("desktop/electron/package.json")
        electron_lock = self._json("desktop/electron/package-lock.json")
        changelog = self._read("CHANGELOG.md")

        self.assertEqual(app.version, TARGET_VERSION)
        self.assertEqual(AGENT_VERSION, TARGET_VERSION)
        self.assertEqual(frontend["version"], TARGET_VERSION)
        self.assertEqual(frontend_lock["version"], TARGET_VERSION)
        self.assertEqual(frontend_lock["packages"][""]["version"], TARGET_VERSION)
        self.assertEqual(electron["version"], TARGET_VERSION)
        self.assertEqual(electron_lock["version"], TARGET_VERSION)
        self.assertEqual(electron_lock["packages"][""]["version"], TARGET_VERSION)
        self.assertRegex(
            changelog,
            rf"## v{re.escape(TARGET_VERSION)} - Agent & Fleet Monitoring Release",
        )
        self.assertIn("## Unreleased", changelog)
        self.assertIn(
            f"## v{TARGET_VERSION} - Agent & Fleet Monitoring Release - 2026-06-05",
            changelog,
        )

    def test_demo_scripts_do_not_print_raw_tokens(self):
        for relative_path in [
            "scripts/dev/start-demo.ps1",
            "scripts/dev/seed-agent-demo.ps1",
        ]:
            script = self._read(relative_path)
            self.assertNotRegex(
                script, r'Write-Host\s+["(].*\$(DemoToken|AgentToken|SensorToken)'
            )
            self.assertNotIn('Write-Output "$DemoToken"', script)
            self.assertNotIn('Write-Output "$AgentToken"', script)

    def test_release_docs_exist_and_readme_links_them(self):
        readme = self._read("README.md")
        for relative_path in [
            "docs/DEPLOYMENT_OVERVIEW.md",
            "docs/RELEASE_QA_CHECKLIST.md",
            "docs/RELEASE_NOTES_v0.2.0.md",
        ]:
            self.assertTrue((REPO_ROOT / relative_path).is_file())
            self.assertIn(relative_path, readme)

        self.assertIn(f"v{TARGET_VERSION}", readme)

    def test_flow_analysis_docs_and_architecture_are_linked(self):
        readme = self._read("README.md")
        architecture = self._read("docs/ARCHITECTURE.md")
        flow_docs = self._read("docs/FLOW_ANALYSIS.md").lower()

        self.assertIn("docs/FLOW_ANALYSIS.md", readme)
        self.assertIn("Flow Analysis", readme)
        self.assertIn("Flow Engine", architecture)
        self.assertIn("Protocol Intelligence", architecture)
        self.assertIn("Conversation Timeline", architecture)
        self.assertIn("no tls decryption", flow_docs)
        self.assertIn("agent mode remains telemetry-only", flow_docs)

    def test_deep_packet_inspection_docs_and_safety_are_linked(self):
        dpi = self._read("docs/DEEP_PACKET_INSPECTION.md")
        readme = self._read("README.md")
        architecture = self._read("docs/ARCHITECTURE.md")
        self.assertIn("DEEP_PACKET_INSPECTION.md", readme)
        self.assertIn("Deep Packet Inspection", readme)
        self.assertIn("Packet Dissector", architecture)
        self.assertIn("No TLS decryption", dpi)
        self.assertIn("No credential collection", dpi)
        for feature in [
            "Saved Display Filters",
            "Packet Search",
            "TCP Analysis",
            "DNS Intelligence",
            "HTTP/TLS Metadata Intelligence",
            "Protocol Statistics",
        ]:
            self.assertIn(feature, readme)
        self.assertIn("core/tcp_analysis.py", architecture)
        self.assertIn("core/dns_intelligence.py", architecture)

    def test_service_attribution_docs_and_boundaries_are_explicit(self):
        service_docs = self._read("docs/SERVICE_ATTRIBUTION.md")
        service_lower = service_docs.lower()
        readme = self._read("README.md")
        architecture = self._read("docs/ARCHITECTURE.md")

        self.assertIn("docs/SERVICE_ATTRIBUTION.md", readme)
        self.assertIn("Service Attribution / Destination Intelligence", readme)
        self.assertIn("ServiceAttributionEngine", architecture)
        self.assertIn("service_fingerprints.json", architecture)
        packaged_spec = self._read("packaging/pyinstaller/netbotpro_backend.spec")
        self.assertIn('"backend/app/data"', packaged_spec)
        self.assertIn("Unknown encrypted destination", service_docs)
        self.assertIn("browser and container", service_lower)
        self.assertIn("no outbound network request", service_lower)
        for boundary in [
            "tls decryption",
            "mitm",
            "credential collection",
            "browser history scraping",
            "cookie/session inspection",
            "command/control",
            "raw payload forwarding",
        ]:
            self.assertIn(boundary, service_lower)

    def test_performance_pipeline_docs_are_linked_and_scoped(self):
        readme = self._read("README.md")
        architecture = self._read("docs/ARCHITECTURE.md")
        performance = self._read("docs/PERFORMANCE_PIPELINE.md")
        performance_lower = performance.lower()

        self.assertIn("docs/PERFORMANCE_PIPELINE.md", readme)
        self.assertIn("Bounded Packet Intake Queue", readme)
        self.assertIn("Flow-aware Worker Pool", readme)
        self.assertIn("Flow-aware Worker Pool", performance)
        self.assertIn("NETBOT_FLOW_WORKER_COUNT", performance)
        self.assertIn("Flow-aware Worker Pool", architecture)
        self.assertIn("Live Ring Buffer", readme)
        self.assertIn("Live Ring Buffer", performance)
        self.assertIn("Live Ring Buffer", architecture)
        self.assertIn("NETBOT_LIVE_RING_PACKET_MAX", performance)
        self.assertIn("GET /api/live/recent", performance)
        self.assertIn("Benchmark / Soak Tests", performance)
        self.assertIn("Performance Benchmark Suite", readme)
        self.assertIn("docs/PERFORMANCE_VALIDATION.md", readme)
        self.assertTrue((REPO_ROOT / "benchmarks/README.md").is_file())
        validation = self._read("docs/PERFORMANCE_VALIDATION.md").lower()
        self.assertIn("safe synthetic benchmark", validation)
        self.assertIn("not a production capacity claim", validation)
        self.assertIn("live capture: disabled", validation)
        self.assertIn("Queue pressure metrics", readme)
        self.assertIn("Ops Snapshot packet queue visibility", readme)
        self.assertIn("NETBOT_PACKET_QUEUE_MAX_SIZE", readme)
        self.assertIn("Performance Pipeline Foundation", architecture)
        self.assertIn("BoundedPacketQueue", architecture)
        self.assertIn("packet queue worker", architecture.lower())
        self.assertIn("WebSocket Event Aggregator", readme)
        self.assertIn("Event Aggregator", architecture)
        self.assertIn("WebSocket Batching / Event Aggregator", performance)
        self.assertIn("NETBOT_WS_PACKET_BATCH_MS", performance)
        self.assertIn("NETBOT_WS_SLOW_CLIENT_POLICY", performance)
        self.assertIn("NETBOT_PACKET_QUEUE_OVERFLOW_POLICY", performance)
        self.assertIn("NETBOT_PACKET_QUEUE_DRAIN_TIMEOUT_SEC", performance)
        self.assertIn("not the complete performance engine", performance_lower)
        self.assertIn("not the complete performance pipeline", performance_lower)
        self.assertIn("websocket batching", performance_lower)
        self.assertIn("batch persistence", performance_lower)
        self.assertIn("BatchPersistenceWriter", architecture)
        self.assertIn("NETBOT_PERSISTENCE_PACKET_BATCH_SIZE", performance)
        self.assertIn("NETBOT_PERSISTENCE_FLOW_BATCH_SIZE", performance)
        self.assertIn("NETBOT_PERSISTENCE_QUEUE_MAX", readme)
        self.assertIn("Audit logging stays outside", architecture)
        self.assertIn("Batch Persistence / Storage Backpressure", performance)
        self.assertIn("write_latency_ms_p95", performance)
        self.assertIn("persistence pressure contributes", performance.lower())
        self.assertEqual(
            readme.count("| Batch Persistence / Storage Backpressure |"), 1
        )
        self.assertIn("Service Attribution / Destination Intelligence", performance)
        self.assertIn("tls decryption", performance_lower)
        self.assertIn("worker pool", performance_lower)
        self.assertIn("not implemented yet", performance_lower)

    def test_agent_release_safety_is_explicit(self):
        combined = "\n".join(
            [
                self._read("docs/AGENT_MODE.md"),
                self._read("docs/RELEASE_QA_CHECKLIST.md"),
                self._read("docs/SAFE_USE_POLICY.md"),
            ]
        ).lower()

        self.assertIn("no command/control", combined)
        self.assertIn("no raw packet", combined)
        self.assertIn("raw payload", combined)
        self.assertIn("pcap forwarding", combined)
        self.assertIn("read-only monitoring", combined)

        release_notes = self._read("docs/RELEASE_NOTES_v0.2.0.md").lower()
        for forbidden_feature in [
            "no command/control",
            "no raw packet",
            "raw payload forwarding",
            "pcap forwarding",
            "agent auto-update",
        ]:
            self.assertIn(forbidden_feature, release_notes)

    def test_release_workflow_has_tags_notes_and_checksums(self):
        workflow = self._read(".github/workflows/release-desktop.yml")

        self.assertIn('- "v*"', workflow)
        self.assertIn("SHA256SUMS-windows.txt", workflow)
        self.assertIn("SHA256SUMS-linux.txt", workflow)
        self.assertIn("body_path: CHANGELOG.md", workflow)
        self.assertIn("Netbotpro-*.exe", workflow)

    def test_github_workflows_use_current_action_runtimes(self):
        workflows = "\n".join(
            [
                self._read(".github/workflows/ci.yml"),
                self._read(".github/workflows/release-desktop.yml"),
            ]
        )

        for action in [
            "actions/checkout@v6",
            "actions/setup-python@v6",
            "actions/setup-node@v6",
            "actions/upload-artifact@v7",
            "actions/download-artifact@v8",
            "softprops/action-gh-release@v3",
        ]:
            self.assertIn(action, workflows)

        for legacy_action in [
            "actions/checkout@v4",
            "actions/setup-python@v5",
            "actions/setup-node@v4",
            "actions/upload-artifact@v4",
            "actions/download-artifact@v4",
            "softprops/action-gh-release@v2",
        ]:
            self.assertNotIn(legacy_action, workflows)


if __name__ == "__main__":
    unittest.main()
