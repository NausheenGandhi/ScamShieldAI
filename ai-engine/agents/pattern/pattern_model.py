import math
from typing import Any, Dict, Iterable, List, Optional, Sequence

try:
    from sklearn.ensemble import IsolationForest
except Exception:  # pragma: no cover - handled gracefully
    IsolationForest = None

FEATURE_ORDER = [
    "messages_5min",
    "messages_15min",
    "messages_1hour",
    "messages_24hour",
    "message_rate_per_hour",
    "message_rate_per_day",
    "burst_count",
    "messages_in_burst",
    "repeat_count",
    "max_similarity",
    "average_similarity",
    "repeated_url_count",
    "unique_url_count",
    "average_interval",
    "interval_std",
    "timing_regularity",
    "change_ratio",
]


class PatternIsolationForest:
    def __init__(self):
        self.model = None
        self.feature_names = FEATURE_ORDER
        self.model_available = IsolationForest is not None

    def prepare_vector(self, features: Dict[str, Any]) -> List[float]:
        return [float(features.get(name, 0.0)) for name in FEATURE_ORDER]

    def score_features(self, features: Dict[str, Any], training_rows: Optional[Sequence[Sequence[float]]] = None) -> Dict[str, Any]:
        if IsolationForest is None:
            return {
                "model_available": False,
                "is_anomaly": False,
                "anomaly_score": None,
                "training_source": "sklearn not installed",
            }

        if training_rows is None:
            return {
                "model_available": False,
                "is_anomaly": False,
                "anomaly_score": None,
                "training_source": "no training data available",
            }

        if len(training_rows) < 10:
            return {
                "model_available": False,
                "is_anomaly": False,
                "anomaly_score": None,
                "training_source": "insufficient historical examples",
            }

        try:
            model = IsolationForest(
                n_estimators=100,
                contamination=0.10,
                random_state=42,
            )
            training_array = [[float(value) for value in row] for row in training_rows]
            model.fit(training_array)
            self.model = model
            self.model_available = True

            sample = self.prepare_vector(features)
            raw_score = float(model.score_samples([sample])[0])
            baseline = model.score_samples(training_array)
            low = float(min(baseline))
            high = float(max(baseline))
            span = high - low if abs(high - low) > 1e-9 else 1.0

            # score_samples returns higher values for more normal points.
            # Convert to a 0..1 anomaly score by inverting and normalizing.
            anomaly_score = 1.0 - ((raw_score - low) / span)
            anomaly_score = max(0.0, min(1.0, anomaly_score))

            return {
                "model_available": True,
                "is_anomaly": anomaly_score >= 0.7,
                "anomaly_score": round(anomaly_score, 3),
                "training_source": "historical behavioral data",
            }
        except Exception:
            return {
                "model_available": False,
                "is_anomaly": False,
                "anomaly_score": None,
                "training_source": "model training failed",
            }


_default_model = PatternIsolationForest()


def get_pattern_model() -> PatternIsolationForest:
    return _default_model


def build_training_rows(rows: Iterable[Iterable[float]]) -> List[List[float]]:
    prepared: List[List[float]] = []
    for row in rows:
        if len(row) != len(FEATURE_ORDER):
            continue
        prepared.append([float(value) for value in row])
    return prepared
