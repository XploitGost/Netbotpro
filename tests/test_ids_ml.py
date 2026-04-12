import unittest
from unittest.mock import patch

from core.ids_ml import MLIDS


class MlIdsTests(unittest.TestCase):
    def test_ml_detector_disables_itself_when_sklearn_is_missing(self):
        detector = MLIDS(sample_rate=1, min_train_size=50)
        packet = {
            "src": "10.0.0.5",
            "dst": "8.8.8.8",
            "proto": "TCP",
            "sport": 55000,
            "dport": 443,
            "length": 220,
            "ttl": 64,
        }

        def fake_import(name):
            if name == "numpy":
                class _FakeNumpy:
                    @staticmethod
                    def asarray(value, dtype=float):
                        return value

                return _FakeNumpy()
            if name == "sklearn.ensemble":
                raise ModuleNotFoundError("sklearn intentionally unavailable")
            raise AssertionError(f"unexpected import: {name}")

        detector._buffer.extend([[1.0, 2.0, 3.0, 4.0, 5.0, 1.0, 0.0] for _ in range(49)])
        detector._since_last_train = 299

        with patch("core.ids_ml.importlib.import_module", side_effect=fake_import):
            self.assertIsNone(detector.analyze_packet(packet))
            self.assertIsNone(detector.analyze_packet(packet))

        self.assertFalse(detector._ml_available)
        self.assertFalse(detector._trained)


if __name__ == "__main__":
    unittest.main()
