import time
import unittest
from unittest.mock import patch

from backend.app.services.sniffer_persistence import SnifferPersistence


class SnifferPersistenceTests(unittest.TestCase):
    @patch("backend.app.services.sniffer_persistence.is_persist_enabled", return_value=True)
    @patch("backend.app.services.sniffer_persistence.insert_batch")
    def test_persistence_batches_rows_off_hot_path(self, mock_insert_batch, _mock_enabled):
        mock_insert_batch.return_value = {"retries": 0}
        persistence = SnifferPersistence(batch_size=2, flush_interval=0.05, max_queue_size=10)
        try:
            persistence.persist({"ts": "1", "src": "a", "dst": "b", "proto": "TCP"}, [])
            persistence.persist({"ts": "2", "src": "c", "dst": "d", "proto": "UDP"}, [{"attack_type": "x", "score": 1}])
            time.sleep(0.2)
        finally:
            persistence.close()

        self.assertTrue(mock_insert_batch.called)
        packet_rows, alert_rows = mock_insert_batch.call_args[0]
        self.assertEqual(len(packet_rows), 2)
        self.assertEqual(len(alert_rows), 1)
        self.assertEqual(packet_rows[1]["remote_ip"], None)
        self.assertEqual(packet_rows[1]["app_protocol"], None)
        self.assertEqual(packet_rows[1]["process_name"], None)
        self.assertEqual(alert_rows[0]["engine"], None)
        stats = persistence.stats()
        self.assertEqual(stats["flush_batches"], 1)
        self.assertEqual(stats["overload_policy"], "drop_oldest")

    @patch("backend.app.services.sniffer_persistence.is_persist_enabled", return_value=True)
    @patch("backend.app.services.sniffer_persistence.insert_batch")
    def test_persistence_keeps_enriched_alert_fields(self, mock_insert_batch, _mock_enabled):
        mock_insert_batch.return_value = {"retries": 0}
        persistence = SnifferPersistence(batch_size=1, flush_interval=0.05, max_queue_size=10)
        try:
            persistence.persist(
                {
                    "id": "cap-77",
                    "ts": "1",
                    "src": "10.0.0.5",
                    "dst": "8.8.8.8",
                    "proto": "TCP",
                    "remote_ip": "8.8.8.8",
                    "protocol_basis": "TLS handshake: TLS1.3",
                    "protocol_handshake": "TLS ClientHello",
                    "payload_entropy": 4.8,
                    "payload_binary_like": True,
                    "pid": 4242,
                    "process_name": "browser.exe",
                    "parent_pid": 4000,
                    "parent_process_name": "explorer.exe",
                    "executable_path": "C:/Program Files/Browser/browser.exe",
                    "attribution_confidence": "high",
                    "attribution_source": "psutil",
                },
                [
                    {
                        "attack_type": "scan",
                        "score": 0.9,
                        "severity": "high",
                        "engine": "RULE",
                        "score_raw": 0.4,
                        "incident_id": "inc-1",
                        "incident_count": 3,
                        "incident_score": 0.8,
                        "packet_id": "mem-pkt-9",
                        "app_protocol": "HTTPS",
                        "app_category": "web",
                        "protocol_basis": "TLS handshake: TLS1.3",
                        "protocol_handshake": "TLS ClientHello",
                        "payload_entropy": 4.8,
                        "payload_binary_like": True,
                        "dns_qname": None,
                        "http_host": "example.com",
                        "http_path": "/admin",
                        "sni": "example.com",
                    }
                ],
            )
            time.sleep(0.2)
        finally:
            persistence.close()

        packet_rows, alert_rows = mock_insert_batch.call_args[0]
        self.assertEqual(packet_rows[0]["capture_id"], "cap-77")
        self.assertEqual(packet_rows[0]["remote_ip"], "8.8.8.8")
        self.assertEqual(packet_rows[0]["protocol_basis"], "TLS handshake: TLS1.3")
        self.assertEqual(packet_rows[0]["protocol_handshake"], "TLS ClientHello")
        self.assertEqual(packet_rows[0]["payload_entropy"], 4.8)
        self.assertTrue(packet_rows[0]["payload_binary_like"])
        self.assertEqual(alert_rows[0]["severity"], "high")
        self.assertEqual(alert_rows[0]["engine"], "RULE")
        self.assertEqual(alert_rows[0]["incident_id"], "inc-1")
        self.assertEqual(alert_rows[0]["packet_id"], "mem-pkt-9")
        self.assertEqual(alert_rows[0]["remote_ip"], "8.8.8.8")
        self.assertEqual(alert_rows[0]["app_protocol"], "HTTPS")
        self.assertEqual(alert_rows[0]["protocol_basis"], "TLS handshake: TLS1.3")
        self.assertEqual(alert_rows[0]["protocol_handshake"], "TLS ClientHello")
        self.assertEqual(alert_rows[0]["payload_entropy"], 4.8)
        self.assertTrue(alert_rows[0]["payload_binary_like"])
        self.assertEqual(alert_rows[0]["http_host"], "example.com")
        self.assertEqual(alert_rows[0]["sni"], "example.com")
        self.assertEqual(packet_rows[0]["process_name"], "browser.exe")
        self.assertEqual(packet_rows[0]["parent_process_name"], "explorer.exe")
        self.assertEqual(alert_rows[0]["pid"], 4242)
        self.assertEqual(alert_rows[0]["attribution_confidence"], "high")

    @patch("backend.app.services.sniffer_persistence.is_persist_enabled", return_value=True)
    @patch("backend.app.services.sniffer_persistence.insert_batch")
    def test_persistence_drop_newest_policy_is_intentional(self, mock_insert_batch, _mock_enabled):
        mock_insert_batch.return_value = {"retries": 0}
        persistence = SnifferPersistence(batch_size=10, flush_interval=1.0, max_queue_size=1, overload_policy="drop_newest")
        try:
            persistence.persist({"ts": "1", "src": "a", "dst": "b", "proto": "TCP"}, [])
            persistence.persist({"ts": "2", "src": "c", "dst": "d", "proto": "TCP"}, [])
            time.sleep(0.2)
        finally:
            persistence.close()

        stats = persistence.stats()
        self.assertGreaterEqual(stats["dropped_writes"], 1)
        self.assertEqual(stats["overload_policy"], "drop_newest")


if __name__ == "__main__":
    unittest.main()
