import importlib.util
import tempfile
import unittest
from pathlib import Path

from log_manager import _df_from_alert_rows, _df_from_packet_rows, export_packets_csv, is_persist_enabled


@unittest.skipUnless(importlib.util.find_spec("pandas") is not None, "pandas is not installed in this environment")
class LogManagerFacadeTests(unittest.TestCase):
    def test_packet_df_keeps_compatibility_columns(self):
        df = _df_from_packet_rows(
            [
                {
                    "timestamp": "10:00:00",
                    "src": "1.1.1.1",
                    "dst": "2.2.2.2",
                    "proto": "TCP",
                    "country_code": "US",
                    "sni": "example.com",
                }
            ]
        )
        self.assertIn("country_code", df.columns)
        self.assertIn("sni", df.columns)
        self.assertEqual(df.iloc[0]["ts"], "10:00:00")

    def test_alert_df_maps_attack_type(self):
        df = _df_from_alert_rows([{"attack_type": "scan", "src": "1.1.1.1"}])
        self.assertEqual(df.iloc[0]["attack"], "scan")

    def test_session_csv_export_works_without_persistence(self):
        self.assertFalse(is_persist_enabled())
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "packets.csv"
            out = export_packets_csv(str(path), packet_rows=[{"ts": "10:00:00", "src": "1.1.1.1"}])
            self.assertEqual(out, str(path))
            self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
