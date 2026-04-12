# ids_ml.py
# -*- coding: utf-8 -*-
"""
Optional ML-based IDS support for NetBotPRO.

The desktop packaged backend does not need sklearn/scipy to boot. Those
dependencies are loaded only when the ML detector actually needs to train.
If they are unavailable, ML detections silently disable themselves instead
of breaking startup or packaging.
"""

from __future__ import annotations

from collections import deque
import importlib
import ipaddress
from typing import Any, Optional


def _load_numpy():
    return importlib.import_module("".join(["num", "py"]))


def _load_isolation_forest():
    module = importlib.import_module("".join(["sk", "learn", ".ensemble"]))
    return module.IsolationForest


def _is_private_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


class MLIDS:
    def __init__(
        self,
        contamination: float = 0.06,
        sample_rate: int = 5,
        min_train_size: int = 200,
        max_buffer: int = 5000,
    ) -> None:
        self.contamination = float(contamination)
        self.sample_rate = max(1, int(sample_rate))
        self.min_train_size = max(50, int(min_train_size))
        self.max_buffer = max_buffer

        self._buffer: deque[list[float]] = deque(maxlen=self.max_buffer)
        self._model: Any | None = None
        self._trained = False
        self._seen_packets = 0
        self._since_last_train = 0
        self._ml_available = True

    def reset_model(self, contamination: Optional[float] = None) -> None:
        if contamination is not None:
            self.contamination = float(contamination)
        self._buffer.clear()
        self._model = None
        self._trained = False
        self._seen_packets = 0
        self._since_last_train = 0

    def _extract_features(self, meta: dict[str, Any]) -> list[float]:
        proto = (meta.get("proto") or "").upper()
        if proto == "TCP":
            proto_id = 1
        elif proto == "UDP":
            proto_id = 2
        elif proto == "ICMP":
            proto_id = 3
        else:
            proto_id = 0

        sport = int(meta.get("sport") or 0)
        dport = int(meta.get("dport") or 0)
        length = int(meta.get("length") or 0)
        ttl = int(meta.get("ttl") or 0)
        high_port = 1 if (sport > 1024 or dport > 1024) else 0
        is_udp = 1 if proto == "UDP" else 0

        return [
            float(proto_id),
            float(sport),
            float(dport),
            float(length),
            float(ttl),
            float(high_port),
            float(is_udp),
        ]

    def _train_if_needed(self) -> None:
        if len(self._buffer) < self.min_train_size:
            return
        if self._since_last_train < 300 and self._trained:
            return

        try:
            np = _load_numpy()
            isolation_forest_cls = _load_isolation_forest()
            x_values = np.asarray(self._buffer, dtype=float)
            self._model = isolation_forest_cls(
                n_estimators=100,
                contamination=self.contamination,
                max_features=1.0,
                bootstrap=False,
                n_jobs=-1,
                random_state=42,
            )
            self._model.fit(x_values)
            self._trained = True
            self._since_last_train = 0
        except ModuleNotFoundError:
            self._ml_available = False
            self._model = None
            self._trained = False
        except Exception:
            self._model = None
            self._trained = False

    def score(self, meta: dict[str, Any]) -> Optional[float]:
        if not self._trained or self._model is None:
            return None

        features = self._extract_features(meta)
        np = _load_numpy()
        x_values = np.asarray([features], dtype=float)
        prediction = self._model.decision_function(x_values)
        if prediction is None or len(prediction) == 0:
            return None

        raw = float(prediction[0])
        score = 0.5 - raw
        if score < 0.0:
            score = 0.0
        if score > 1.0:
            score = 1.0
        return score

    def analyze_packet(self, meta: dict[str, Any], threshold: float = 0.25) -> Optional[dict[str, Any]]:
        self._seen_packets += 1

        if (self._seen_packets % self.sample_rate) != 0:
            return None

        src = meta.get("src")
        dst = meta.get("dst")
        if _is_private_ip(src) and _is_private_ip(dst):
            return None

        length = int(meta.get("length") or 0)
        if length < 80:
            return None

        features = self._extract_features(meta)
        self._buffer.append(features)
        self._since_last_train += 1
        self._train_if_needed()

        if not self._ml_available:
            return None
        if not self._trained or self._model is None:
            return None

        try:
            score = self.score(meta)
        except Exception:
            return None

        if score is None or score < threshold:
            return None

        detail = (
            "This is unusual traffic detected by the ML anomaly model. "
            "It may be caused by automated probing, scanning, or a new unknown pattern."
        )
        return {
            "attack_type": "ML Anomaly / Robot Detection",
            "detail": detail,
            "score": float(score),
        }
