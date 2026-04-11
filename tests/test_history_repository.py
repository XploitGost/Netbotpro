import asyncio
import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.app.repositories.history_repository import AlertListQuery, MemoryHistoryRepository, PacketListQuery, SQLiteHistoryRepository


class _FakeSnifferService:
    def recent_packets(self):
        return [
            {"id": "mem-pkt-2", "src": "10.0.0.2", "dst": "8.8.8.8", "proto": "UDP", "summary": "two", "remote_ip": "8.8.8.8", "app_protocol": "DNS", "dns_qname": "api.example.com"},
            {"id": "mem-pkt-1", "src": "10.0.0.1", "dst": "1.1.1.1", "proto": "TCP", "summary": "one", "remote_ip": "1.1.1.1", "app_protocol": "HTTPS", "sni": "example.com"},
        ]

    def recent_alerts(self):
        return [
            {"id": "mem-alert-2", "src": "8.8.8.8", "dst": "10.0.0.2", "attack_type": "Burst", "score": 1.0, "detail": "two", "remote_ip": "8.8.8.8", "app_protocol": "DNS"},
            {"id": "mem-alert-1", "src": "1.1.1.1", "dst": "10.0.0.1", "attack_type": "Scan", "score": 0.5, "detail": "one", "remote_ip": "1.1.1.1", "app_protocol": "HTTPS"},
        ]


class MemoryHistoryRepositoryTests(unittest.TestCase):
    def test_memory_detail_lookup_uses_stable_packet_id(self):
        repository = MemoryHistoryRepository(_FakeSnifferService())

        packet = repository.get_packet_detail("mem-pkt-1")

        self.assertIsNotNone(packet)
        self.assertEqual(packet["src"], "10.0.0.1")

    def test_memory_detail_lookup_uses_stable_alert_id(self):
        repository = MemoryHistoryRepository(_FakeSnifferService())

        alert = repository.get_alert_detail("mem-alert-2")

        self.assertIsNotNone(alert)
        self.assertEqual(alert["attack_type"], "Burst")

    def test_only_remote_filter_keeps_external_flows(self):
        repository = MemoryHistoryRepository(_FakeSnifferService())

        result = repository.list_packets(PacketListQuery(only_remote=True))

        self.assertEqual(result["total"], 2)
        self.assertEqual(result["items"][0]["dst"], "8.8.8.8")


class SQLiteHistoryRepositoryTests(unittest.TestCase):
    def test_sqlite_alert_queries_keep_enriched_fields(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "history.db"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        length INTEGER,
                        country TEXT,
                        org TEXT,
                        summary TEXT,
                        is_alert INTEGER DEFAULT 0,
                        remote_ip TEXT,
                        app_protocol TEXT,
                        app_category TEXT,
                        app_confidence TEXT,
                        l7 TEXT,
                        dns_qname TEXT,
                        http_host TEXT,
                        http_path TEXT,
                        sni TEXT,
                        tls_version TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        attack_type TEXT,
                        score REAL,
                        detail TEXT,
                        severity TEXT,
                        engine TEXT,
                        score_raw REAL,
                        incident_id TEXT,
                        incident_count INTEGER,
                        incident_score REAL,
                        packet_id TEXT,
                        remote_ip TEXT,
                        app_protocol TEXT,
                        app_category TEXT,
                        app_confidence TEXT,
                        dns_qname TEXT,
                        http_host TEXT,
                        http_path TEXT,
                        sni TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO alerts (
                        ts, src, dst, proto, attack_type, score, detail,
                        severity, engine, score_raw, incident_id,
                        incident_count, incident_score, packet_id, remote_ip,
                        app_protocol, app_category, app_confidence, dns_qname,
                        http_host, http_path, sni
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "10:00:00",
                        "8.8.8.8",
                        "10.0.0.2",
                        "TCP",
                        "Burst",
                        0.95,
                        "detail",
                        "HIGH",
                        "RULE",
                        0.4,
                        "inc-9",
                        2,
                        0.88,
                        "mem-pkt-4",
                        "8.8.8.8",
                        "HTTPS",
                        "web",
                        "high",
                        None,
                        "example.com",
                        "/admin",
                        "example.com",
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            repository = SQLiteHistoryRepository(db_path=str(db_path))
            alerts = repository.list_alerts(AlertListQuery(limit=50, offset=0))
            detail = repository.get_alert_detail("1")

            self.assertEqual(alerts["items"][0]["severity"], "HIGH")
            self.assertEqual(alerts["items"][0]["engine"], "RULE")
            self.assertEqual(alerts["items"][0]["incident_id"], "inc-9")
            self.assertEqual(alerts["items"][0]["app_protocol"], "HTTPS")
            self.assertEqual(detail["packet_id"], "mem-pkt-4")
            self.assertEqual(detail["remote_ip"], "8.8.8.8")
            self.assertEqual(detail["http_host"], "example.com")

    def test_async_wrapper_matches_sync_result(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "history.db"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        length INTEGER,
                        country TEXT,
                        org TEXT,
                        summary TEXT,
                        is_alert INTEGER DEFAULT 0,
                        remote_ip TEXT,
                        app_protocol TEXT,
                        app_category TEXT,
                        app_confidence TEXT,
                        l7 TEXT,
                        dns_qname TEXT,
                        http_host TEXT,
                        http_path TEXT,
                        sni TEXT,
                        tls_version TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO packets (
                        ts, src, dst, proto, sport, dport, length,
                        country, org, summary, is_alert, remote_ip,
                        app_protocol, app_category, app_confidence, l7,
                        dns_qname, http_host, http_path, sni, tls_version
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("10:00:00", "10.0.0.1", "8.8.8.8", "TCP", 1234, 80, 60, "US", "Example", "hello", 1, "8.8.8.8", "HTTP", "web", "high", "HTTP GET /", None, "example.com", "/", None, None),
                )
                conn.commit()
            finally:
                conn.close()

            repository = SQLiteHistoryRepository(db_path=str(db_path))
            sync_result = repository.list_packets(PacketListQuery(text="hello", limit=50, offset=0))
            async_result = asyncio.run(repository.alist_packets(PacketListQuery(text="hello", limit=50, offset=0)))

            self.assertEqual(sync_result, async_result)


if __name__ == "__main__":
    unittest.main()
