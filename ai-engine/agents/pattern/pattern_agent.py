import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .pattern_features import compute_feature_vector
from .pattern_history import normalize_sender, record_pattern_message, get_pattern_history, get_sender_mongo_history
from .pattern_model import build_training_rows, get_pattern_model


def _pattern_level(score: Optional[int]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 75:
        return "HIGH"
    if score >= 45:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "LOW"


def _score_pattern(
    features: Dict[str, Any],
    signals: Dict[str, bool],
    anomaly_result: Dict[str, Any],
) -> int:
    score = 0

    if features.get("messages_5min", 0) >= 3:
        score += 18
    if features.get("messages_15min", 0) >= 6:
        score += 8
    if features.get("messages_1hour", 0) >= 10:
        score += 10
    if features.get("messages_24hour", 0) >= 30:
        score += 8

    if features.get("burst_detected"):
        score += 18
    if features.get("repeated_content"):
        score += 20
    if features.get("repeated_url"):
        score += 16
    if features.get("unusual_timing"):
        score += 12
    if features.get("sudden_volume_change"):
        score += 12
    if anomaly_result.get("anomaly_score") is not None:
        score += int(round(anomaly_result["anomaly_score"] * 35))

    if signals.get("high_frequency"):
        score += 10
    if signals.get("repeated_content"):
        score += 8
    if signals.get("repeated_url"):
        score += 8

    return max(0, min(100, score))


def _build_reasons(features: Dict[str, Any], signals: Dict[str, bool], anomaly_result: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []

    if features.get("messages_5min", 0) >= 3:
        reasons.append(f"Sender sent {features.get('messages_5min')} messages in 5 minutes.")
    elif features.get("messages_15min", 0) >= 5:
        reasons.append(f"Sender sent {features.get('messages_15min')} messages in 15 minutes.")

    if features.get("burst_detected"):
        reasons.append(
            f"Burst pattern detected: {features.get('messages_in_burst')} messages in {features.get('burst_window_seconds')} seconds."
        )

    if features.get("repeated_content"):
        reasons.append(
            "Current message is highly similar to previous messages from this sender."
        )

    if features.get("repeated_url"):
        reasons.append("The same URL or URL pattern is being repeated by this sender.")

    if features.get("unusual_timing"):
        reasons.append("Sending intervals are unusually regular, suggesting automated behavior.")

    if features.get("sudden_volume_change"):
        reasons.append("Message volume increased sharply relative to recent activity.")

    if anomaly_result.get("is_anomaly"):
        reasons.append("Behavioral anomaly score suggests this sender is acting unusually for this pattern history.")

    if not reasons:
        reasons.append("No unusual behavioral pattern indicators detected.")

    return reasons


def analyze_pattern(
    sender: str,
    message: str,
    timestamp: Optional[float] = None,
    history: Optional[List[Tuple[float, str]]] = None,
) -> Dict[str, Any]:
    sender_key = normalize_sender(sender)
    now = timestamp if timestamp is not None else time.time()

    if message is None:
        message = ""

    if history is None:
        history = get_pattern_history(sender_key, timestamp=now)

    if not isinstance(history, list):
        history = []

    history = sorted(history, key=lambda item: item[0])
    if message.strip():
        history = [*history, (now, message)]
        history = sorted(history, key=lambda item: item[0])

    mongodb_snapshot = get_sender_mongo_history(sender_key, hours=24)
    feature_vector = compute_feature_vector(history, message, now=now)

    training_rows = []
    if mongodb_snapshot.get("available") and mongodb_snapshot.get("count", 0) > 0:
        training_rows = [
            [
                0.0,
                0.0,
                0.0,
                max(1.0, float(mongodb_snapshot.get("count", 0))),
                1.0,
                0.5,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                1.0,
                60.0,
                5.0,
                0.0,
                0.0,
            ]
        ]

    model = get_pattern_model()
    anomaly_result = model.score_features(feature_vector, training_rows=build_training_rows(training_rows))
    signals = {
        "high_frequency": bool(feature_vector.get("messages_5min", 0) >= 3 or feature_vector.get("messages_15min", 0) >= 5 or feature_vector.get("messages_1hour", 0) >= 10),
        "burst_detected": bool(feature_vector.get("burst_detected", False)),
        "repeated_content": bool(feature_vector.get("repeated_content", False)),
        "repeated_url": bool(feature_vector.get("repeated_url", False)),
        "unusual_timing": bool(feature_vector.get("unusual_timing", False)),
        "sudden_volume_increase": bool(feature_vector.get("sudden_volume_change", False)),
        "anomaly_detected": bool(anomaly_result.get("is_anomaly", False)),
    }

    pattern_score = _score_pattern(feature_vector, signals, anomaly_result)
    pattern_risk = _pattern_level(pattern_score) if history else "UNKNOWN"

    if not message.strip() or not sender_key or sender_key == "unknown":
        pattern_score = None
        pattern_risk = "UNKNOWN"
        anomaly_result = {"model_available": False, "is_anomaly": False, "anomaly_score": None, "training_source": "insufficient input"}
        signals = {
            "high_frequency": False,
            "burst_detected": False,
            "repeated_content": False,
            "repeated_url": False,
            "unusual_timing": False,
            "sudden_volume_increase": False,
            "anomaly_detected": False,
        }

    reasons = _build_reasons(feature_vector, signals, anomaly_result)

    return {
        "sender": {
            "normalized": sender_key,
        },
        "pattern_risk": pattern_risk,
        "pattern_score": pattern_score,
        "anomaly_score": anomaly_result.get("anomaly_score"),
        "model_available": bool(anomaly_result.get("model_available", False)),
        "history_available": bool(history),
        "database_history_available": bool(mongodb_snapshot.get("available", False)),
        "signals": signals,
        "features": {
            "messages_5min": feature_vector.get("messages_5min", 0),
            "messages_15min": feature_vector.get("messages_15min", 0),
            "messages_1hour": feature_vector.get("messages_1hour", 0),
            "messages_24hour": feature_vector.get("messages_24hour", 0),
            "message_rate_per_hour": feature_vector.get("message_rate_per_hour", 0.0),
            "message_rate_per_day": feature_vector.get("message_rate_per_day", 0.0),
            "burst_detected": feature_vector.get("burst_detected", False),
            "burst_count": feature_vector.get("burst_count", 0),
            "burst_window_seconds": feature_vector.get("burst_window_seconds", 300),
            "messages_in_burst": feature_vector.get("messages_in_burst", 0),
            "repeat_count": feature_vector.get("repeat_count", 0),
            "max_similarity": feature_vector.get("max_similarity", 0.0),
            "average_similarity": feature_vector.get("average_similarity", 0.0),
            "repeated_content": feature_vector.get("repeated_content", False),
            "repeated_url": feature_vector.get("repeated_url", False),
            "repeated_url_count": feature_vector.get("repeated_url_count", 0),
            "unique_url_count": feature_vector.get("unique_url_count", 0),
            "average_interval": feature_vector.get("average_interval", 0.0),
            "median_interval": feature_vector.get("median_interval", 0.0),
            "interval_std": feature_vector.get("interval_std", 0.0),
            "min_interval": feature_vector.get("min_interval", 0.0),
            "max_interval": feature_vector.get("max_interval", 0.0),
            "timing_regularity": feature_vector.get("timing_regularity", 0.0),
            "unusual_timing": feature_vector.get("unusual_timing", False),
            "sudden_volume_change": feature_vector.get("sudden_volume_change", False),
            "change_ratio": feature_vector.get("change_ratio", 0.0),
        },
        "reasons": reasons,
        "training_source": anomaly_result.get("training_source", "not_available"),
        "pattern": {
            "risk": pattern_risk,
            "score": pattern_score,
            "anomaly_score": anomaly_result.get("anomaly_score"),
            "signals": signals,
            "features": {
                "messages_5min": feature_vector.get("messages_5min", 0),
                "messages_15min": feature_vector.get("messages_15min", 0),
                "messages_1hour": feature_vector.get("messages_1hour", 0),
                "messages_24hour": feature_vector.get("messages_24hour", 0),
                "burst_detected": feature_vector.get("burst_detected", False),
                "repeated_content": feature_vector.get("repeated_content", False),
                "repeated_url": feature_vector.get("repeated_url", False),
            },
        },
    }
