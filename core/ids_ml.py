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

from collections import deque, OrderedDict
import threading
import importlib
import ipaddress
import time
from typing import Any, Optional, Callable


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
        background_training: bool = False,
        min_retrain_seconds: float = 0.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.contamination = float(contamination)
        self.sample_rate = max(1, int(sample_rate))
        self.min_train_size = max(50, int(min_train_size))
        self.max_buffer = max_buffer
        self.background_training = bool(background_training)
        self.min_retrain_seconds = max(0.0, float(min_retrain_seconds))
        self._clock = clock or time.monotonic
        self._last_train_attempt = None
        self._training_attempts = self._training_successes = self._training_failures = 0
        self._score_cache_hits = self._score_cache_misses = 0
        self._scoring_errors = 0
        self._last_scoring_error = ''

        self._buffer: deque[list[float]] = deque(maxlen=self.max_buffer)
        self._model: Any | None = None
        self._trained = False
        self._seen_packets = 0
        self._since_last_train = 0
        self._ml_available = True
        self._state_lock = threading.RLock()
        self._score_cache_model = None
        self._score_cache = OrderedDict()
        self._batch_keys: set[tuple[float, ...]] = set()
        self._prime_calls = self._prime_features = self._prime_failures = 0
        self._training_pending = False
        self._generation = 0
        self._training_thread: threading.Thread | None = None

    def reset_model(self, contamination: Optional[float] = None) -> None:
        with self._state_lock:
            self._reset_model_locked(contamination)

    def _reset_model_locked(self, contamination: Optional[float]) -> None:
        self._generation += 1
        self._training_pending = False
        if contamination is not None:
            self.contamination = float(contamination)
        self._buffer.clear()
        self._model = None
        self._score_cache_model = None
        self._score_cache.clear()
        self._batch_keys.clear()
        self._prime_calls = self._prime_features = self._prime_failures = 0
        self._trained = False
        self._seen_packets = 0
        self._since_last_train = 0
        self._ml_available = True
        self._last_train_attempt = None
        self._training_attempts = self._training_successes = self._training_failures = 0
        self._score_cache_hits = self._score_cache_misses = 0
        self._scoring_errors = 0
        self._last_scoring_error = ''

    def _train_in_background(self, samples: list[list[float]], generation: int, contamination: float) -> None:
        model = None
        missing_dependency = False
        try:
            np = _load_numpy()
            isolation_forest_cls = _load_isolation_forest()
            model = isolation_forest_cls(
                n_estimators=100, contamination=contamination, max_features=1.0,
                bootstrap=False, n_jobs=1, random_state=42,
            )
            model.fit(np.asarray(samples, dtype=float))
        except ModuleNotFoundError:
            missing_dependency = True
        except Exception:
            pass
        with self._state_lock:
            if generation != self._generation:
                return
            self._training_pending = False
            if missing_dependency:
                self._ml_available = False
                self._model = None
                self._trained = False
            elif model is not None:
                self._model = model
                self._trained = True
                self._since_last_train = 0
                self._training_successes += 1
            if model is None:
                self._training_failures += 1

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
        if not self._ml_available:
            return
        if len(self._buffer) < self.min_train_size:
            return
        if self._since_last_train < 300 and self._trained:
            return
        if self._training_pending:
            return
        now = self._clock()
        if self._last_train_attempt is not None and now-self._last_train_attempt < self.min_retrain_seconds:
            return
        self._last_train_attempt = now
        self._training_attempts += 1
        if self.background_training:
            self._training_pending = True
            self._training_thread = threading.Thread(
                target=self._train_in_background,
                args=(list(self._buffer), self._generation, self.contamination),
                name="netbotpro-ml-training",
                daemon=True,
            )
            try:
                self._training_thread.start()
            except Exception:
                self._training_pending = False
                self._training_failures += 1
                raise
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
                n_jobs=1,
                random_state=42,
            )
            self._model.fit(x_values)
            self._trained = True
            self._since_last_train = 0
            self._training_successes += 1
        except ModuleNotFoundError:
            self._training_failures += 1
            self._ml_available = False
            self._model = None
            self._trained = False
        except Exception:
            self._training_failures += 1
            self._model = None
            self._trained = False

    def score(self, meta: dict[str, Any]) -> Optional[float]:
        if not self._trained or self._model is None:
            return None

        features = self._extract_features(meta)
        return self._score_model(self._model, features)

    @staticmethod
    def _score_model(model: Any, features: list[float]) -> Optional[float]:
        np = _load_numpy()
        x_values = np.asarray([features], dtype=float)
        prediction = model.decision_function(x_values)
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
        with self._state_lock:
            model, features = self._prepare_packet_locked(meta)
        if model is None:
            return None
        try:
            score = self._cached_model_score(model, features, threshold=threshold)
        except Exception as exc:
            with self._state_lock:
                self._scoring_errors += 1
                self._last_scoring_error = type(exc).__name__
            raise
        if score is None or score < threshold:
            return None

        detail = (
            "This is unusual traffic detected by the ML anomaly model. "
            "It may be caused by automated probing, scanning, or a new unknown pattern."
        )
        return {
            "attack_type": "ML Anomaly / Robot Detection",
            "detection_rule_key": "ml.anomaly",
            "detection_rule_version": "1",
            "detail": detail,
            "score": float(score),
        }

    def _cached_model_score(self, model: Any, features: list[float], *, threshold=None) -> Optional[float]:
        key = tuple(features)
        with self._state_lock:
            if self._score_cache_model is not model:
                self._score_cache_model = model
                self._score_cache.clear()
                self._batch_keys.clear()
            if key in self._score_cache:
                cached = self._score_cache[key]
                # Preserve scalar threshold decisions at floating-point boundaries.
                if (threshold is None or key not in self._batch_keys or cached is None
                        or abs(cached - threshold) > 1e-12):
                    self._score_cache_hits += 1
                    self._score_cache.move_to_end(key)
                    return cached
            self._score_cache_misses += 1
        score = self._score_model(model, features)
        with self._state_lock:
            if self._score_cache_model is model:
                self._score_cache[key] = score
                self._batch_keys.discard(key)
                self._score_cache.move_to_end(key)
                while len(self._score_cache) > 1024:
                    expired, _ = self._score_cache.popitem(last=False)
                    self._batch_keys.discard(expired)
        return score

    def prime_scores(self, packets: list[dict[str, Any]]) -> None:
        """Precompute only; sampling, training and alert decisions stay per packet."""
        with self._state_lock:
            model = self._model
            if not self._trained or model is None or not self._ml_available:
                return
            generation = self._generation
            seen = self._seen_packets
            if self._score_cache_model is not model:
                self._score_cache_model = model
                self._score_cache.clear()
                self._batch_keys.clear()
            missing = {}
            for offset, packet in enumerate(packets[:32], 1):
                if (seen + offset) % self.sample_rate:
                    continue
                if _is_private_ip(packet.get('src')) and _is_private_ip(packet.get('dst')):
                    continue
                if int(packet.get('length') or 0) < 80:
                    continue
                features = self._extract_features(packet)
                key = tuple(features)
                if key not in self._score_cache:
                    missing[key] = features
            if len(missing) < 2:
                return
        try:
            np = _load_numpy()
            predictions = model.decision_function(np.asarray(list(missing.values()), dtype=float))
            if predictions is None or len(predictions) != len(missing):
                raise ValueError('Incomplete batched ML scores')
            scores = [max(0.0, min(1.0, 0.5 - float(raw))) for raw in predictions]
            if not all(np.isfinite(raw) for raw in predictions):
                raise ValueError('Non-finite batched ML scores')
        except Exception:
            # The original scalar path still runs and reports any real scoring failure.
            with self._state_lock:
                self._prime_failures += 1
            return
        with self._state_lock:
            if self._generation != generation or self._model is not model or self._score_cache_model is not model:
                return
            self._prime_calls += 1
            self._prime_features += len(missing)
            for key, score in zip(missing, scores):
                if key not in self._score_cache:
                    self._score_cache[key] = score
                    self._batch_keys.add(key)
            while len(self._score_cache) > 1024:
                expired, _ = self._score_cache.popitem(last=False)
                self._batch_keys.discard(expired)

    def training_stats(self) -> dict[str, Any]:
        with self._state_lock:
            return dict(min_retrain_seconds=self.min_retrain_seconds,
                        model_ready=self._trained and self._model is not None,
                        training_attempts=self._training_attempts,
                        training_successes=self._training_successes,
                        training_failures=self._training_failures,
                        training_pending=self._training_pending,
                        score_cache_hits=self._score_cache_hits,
                        score_cache_misses=self._score_cache_misses,
                        scoring_errors_total=self._scoring_errors,
                        last_scoring_error=self._last_scoring_error,
                        score_prime_batches=self._prime_calls,
                        score_prime_features=self._prime_features,
                        score_prime_failures=self._prime_failures)

    def _prepare_packet_locked(self, meta: dict[str, Any]) -> tuple[Any | None, list[float]]:
        self._seen_packets += 1

        if (self._seen_packets % self.sample_rate) != 0:
            return None, []

        src = meta.get("src")
        dst = meta.get("dst")
        if _is_private_ip(src) and _is_private_ip(dst):
            return None, []

        length = int(meta.get("length") or 0)
        if length < 80:
            return None, []

        features = self._extract_features(meta)
        self._buffer.append(features)
        self._since_last_train += 1
        self._train_if_needed()

        if not self._ml_available:
            return None, []
        if not self._trained or self._model is None:
            return None, []
        return self._model, features
