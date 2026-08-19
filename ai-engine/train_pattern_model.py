"""
Training helper for the Pattern Agent.

This repository does not currently include labeled scam/non-scam behavioral data,
so this script intentionally does not claim a trained model exists. It provides a
safe, repeatable procedure for training an IsolationForest once historical sender
behavior data is available.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List

from agents.pattern.pattern_model import PatternIsolationForest, build_training_rows


FEATURE_PATH = Path(__file__).resolve().parent / "pattern_training_features.jsonl"


def load_training_rows(path: Path) -> List[List[float]]:
    if not path.exists():
        return []

    rows: List[List[float]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            if isinstance(payload, dict):
                values = [
                    payload.get("messages_5min", 0),
                    payload.get("messages_15min", 0),
                    payload.get("messages_1hour", 0),
                    payload.get("messages_24hour", 0),
                    payload.get("message_rate_per_hour", 0.0),
                    payload.get("message_rate_per_day", 0.0),
                    payload.get("burst_count", 0),
                    payload.get("messages_in_burst", 0),
                    payload.get("repeat_count", 0),
                    payload.get("max_similarity", 0.0),
                    payload.get("average_similarity", 0.0),
                    payload.get("repeated_url_count", 0),
                    payload.get("unique_url_count", 0),
                    payload.get("average_interval", 0.0),
                    payload.get("interval_std", 0.0),
                    payload.get("timing_regularity", 0.0),
                    payload.get("change_ratio", 0.0),
                ]
                rows.append(values)
    return rows


def main() -> Dict[str, Any]:
    rows = load_training_rows(FEATURE_PATH)
    if not rows:
        return {
            "status": "no_training_data",
            "message": "Place historical behavioral features into pattern_training_features.jsonl before training.",
        }

    model = PatternIsolationForest()
    result = model.score_features({
        "messages_5min": rows[0][0],
        "messages_15min": rows[0][1],
        "messages_1hour": rows[0][2],
        "messages_24hour": rows[0][3],
        "message_rate_per_hour": rows[0][4],
        "message_rate_per_day": rows[0][5],
        "burst_count": rows[0][6],
        "messages_in_burst": rows[0][7],
        "repeat_count": rows[0][8],
        "max_similarity": rows[0][9],
        "average_similarity": rows[0][10],
        "repeated_url_count": rows[0][11],
        "unique_url_count": rows[0][12],
        "average_interval": rows[0][13],
        "interval_std": rows[0][14],
        "timing_regularity": rows[0][15],
        "change_ratio": rows[0][16],
    }, training_rows=build_training_rows(rows))

    return {
        "status": "trained" if result.get("model_available") else "not_trained",
        "training_examples": len(rows),
        "model_available": result.get("model_available", False),
        "feature_order": model.feature_names,
        "anomaly_score": result.get("anomaly_score"),
    }


if __name__ == "__main__":
    print(main())
