import unittest

from backend.app.services.sniffer_dashboard_state import SnifferDashboardState


class SnifferDashboardStateTests(unittest.TestCase):
    def test_add_packet_updates_totals_and_counters(self):
        state = SnifferDashboardState(max_items=5)

        state.add_packet({"src": "192.168.1.10", "dst": "2.2.2.2", "proto": "tcp", "ts": "now", "remote_ip": "2.2.2.2"})
        dashboard = state.dashboard(running=True, iface="eth0")

        self.assertEqual(dashboard["state"]["total_packets"], 1)
        self.assertEqual(dashboard["state"]["packet_count"], 1)
        self.assertEqual(dashboard["top_sources"][0]["label"], "192.168.1.10")
        self.assertEqual(dashboard["top_protocols"][0]["label"], "TCP")
        self.assertEqual(dashboard["top_remotes"][0]["label"], "2.2.2.2")
        self.assertIn("192.168.1.10 -> 2.2.2.2", dashboard["top_conversations"][0]["label"])

    def test_add_alerts_updates_total_and_recent_order(self):
        state = SnifferDashboardState(max_items=5)

        state.add_alerts([
            {"ts": "1", "attack_type": "A"},
            {"ts": "2", "attack_type": "B"},
        ])

        alerts = state.recent_alerts()
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["attack_type"], "A")
        self.assertEqual(state.state(running=False, iface=None)["total_alerts"], 2)

    def test_reset_clears_recent_buffers_and_totals(self):
        state = SnifferDashboardState(max_items=5)

        state.add_packet({"src": "1.1.1.1", "dst": "2.2.2.2", "proto": "tcp", "ts": "now"})
        state.add_alerts([{"ts": "1", "attack_type": "A"}])
        state.reset()

        dashboard = state.dashboard(running=False, iface=None)
        self.assertEqual(dashboard["state"]["total_packets"], 0)
        self.assertEqual(dashboard["state"]["total_alerts"], 0)
        self.assertEqual(dashboard["recent_packets"], [])
        self.assertEqual(dashboard["recent_alerts"], [])

    def test_dashboard_prefers_public_remote_ip_over_stale_local_remote(self):
        state = SnifferDashboardState(max_items=5)

        state.add_packet(
            {
                "src": "192.168.1.10",
                "dst": "8.8.8.8",
                "proto": "tcp",
                "ts": "now",
                "remote_ip": "192.168.1.1",
            }
        )

        dashboard = state.dashboard(running=True, iface="eth0")

        self.assertEqual(dashboard["top_remotes"][0]["label"], "8.8.8.8")


if __name__ == "__main__":
    unittest.main()
