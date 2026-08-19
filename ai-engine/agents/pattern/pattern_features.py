import math
import re
import statistics
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import difflib

SIMILARITY_THRESHOLD = 0.82
BURST_WINDOW_SECONDS = 5 * 60
BURST_MESSAGE_THRESHOLD = 3


def normalize_text(value: str) -> str:
    return " ".join((value or "").strip().split()).lower()


def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    matches = re.findall(r"https?://[^\s)\]>]+", text)
    cleaned = []
    for url in matches:
        cleaned.append(url.rstrip(".,;)]"))
    return cleaned


def normalize_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    base = parsed.netloc.lower()
    path = parsed.path or "/"
    return f"{base}{path}"


def compute_frequency_features(
    history: List[Tuple[float, str]],
    now: Optional[float] = None,
) -> Dict[str, Any]:
    now = now if now is not None else time.time()

    if not history:
        return {
            "messages_5min": 0,
            "messages_15min": 0,
            "messages_1hour": 0,
            "messages_24hour": 0,
            "message_rate_per_hour": 0.0,
            "message_rate_per_day": 0.0,
        }

    times = [ts for ts, _ in history]
    count_5min = sum(1 for ts in times if now - ts <= 5 * 60)
    count_15min = sum(1 for ts in times if now - ts <= 15 * 60)
    count_1hour = sum(1 for ts in times if now - ts <= 60 * 60)
    count_24hour = sum(1 for ts in times if now - ts <= 24 * 60 * 60)

    period_hours = max((max(times) - min(times)) / 3600.0, 1.0) if len(times) > 1 else 1.0
    message_rate_per_hour = round(len(history) / period_hours, 3)
    message_rate_per_day = round(count_24hour / 24.0, 3) if count_24hour else 0.0

    return {
        "messages_5min": int(count_5min),
        "messages_15min": int(count_15min),
        "messages_1hour": int(count_1hour),
        "messages_24hour": int(count_24hour),
        "message_rate_per_hour": message_rate_per_hour,
        "message_rate_per_day": message_rate_per_day,
    }


def detect_burst(
    history: List[Tuple[float, str]],
    now: Optional[float] = None,
    window_seconds: int = BURST_WINDOW_SECONDS,
    threshold: int = BURST_MESSAGE_THRESHOLD,
) -> Dict[str, Any]:
    now = now if now is not None else time.time()
    if len(history) < threshold:
        return {
            "burst_detected": False,
            "burst_count": 0,
            "burst_window_seconds": window_seconds,
            "messages_in_burst": 0,
            "burst_start": None,
            "burst_end": None,
        }

    timestamps = [ts for ts, _ in history]
    best_count = 0
    best_start = None
    best_end = None

    for start_index, start_time in enumerate(timestamps):
        end_time = start_time + window_seconds
        count = 0
        for ts in timestamps[start_index:]:
            if ts <= end_time:
                count += 1
            else:
                break

        if count > best_count:
            best_count = count
            best_start = start_time
            best_end = min(ts for ts in timestamps[start_index:start_index + count]) if count else start_time

    burst_detected = best_count >= threshold

    return {
        "burst_detected": burst_detected,
        "burst_count": 1 if burst_detected else 0,
        "burst_window_seconds": window_seconds,
        "messages_in_burst": best_count,
        "burst_start": best_start,
        "burst_end": best_end,
    }


def compute_repetition_features(
    history: List[Tuple[float, str]],
    current_message: str,
) -> Dict[str, Any]:
    previous_messages = [msg for _, msg in history[:-1]] if history else []
    if not previous_messages or not current_message:
        return {
            "repeated_content": False,
            "repeat_count": 0,
            "max_similarity": 0.0,
            "average_similarity": 0.0,
            "similarity_method": "SequenceMatcher",
        }

    current_clean = normalize_text(current_message)
    if not current_clean:
        return {
            "repeated_content": False,
            "repeat_count": 0,
            "max_similarity": 0.0,
            "average_similarity": 0.0,
            "similarity_method": "SequenceMatcher",
        }

    similarities = []
    for past in previous_messages:
        past_clean = normalize_text(past)
        if not past_clean:
            continue
        ratio = difflib.SequenceMatcher(None, current_clean, past_clean).ratio()
        similarities.append(ratio)

    if not similarities:
        return {
            "repeated_content": False,
            "repeat_count": 0,
            "max_similarity": 0.0,
            "average_similarity": 0.0,
            "similarity_method": "SequenceMatcher",
        }

    max_similarity = max(similarities)
    average_similarity = sum(similarities) / len(similarities)
    repeat_count = sum(1 for value in similarities if value >= SIMILARITY_THRESHOLD)

    return {
        "repeated_content": repeat_count >= 1,
        "repeat_count": int(repeat_count),
        "max_similarity": round(max_similarity, 3),
        "average_similarity": round(average_similarity, 3),
        "similarity_method": "SequenceMatcher",
    }


def compute_url_repetition_features(
    history: List[Tuple[float, str]],
    current_message: str,
) -> Dict[str, Any]:
    current_urls = [normalize_url(url) for url in extract_urls(current_message)]
    previous_urls = []
    for _, previous_message in history[:-1]:
        previous_urls.extend([normalize_url(url) for url in extract_urls(previous_message)])

    repeated_exact = [url for url in current_urls if url and url in previous_urls]
    unique_url_count = len(set(current_urls + previous_urls))

    return {
        "repeated_url": bool(repeated_exact),
        "repeated_url_count": len(repeated_exact),
        "unique_url_count": int(unique_url_count),
        "repeated_url_pattern": bool(repeated_exact),
    }


def compute_timing_features(history: List[Tuple[float, str]]) -> Dict[str, Any]:
    if len(history) < 2:
        return {
            "average_interval": 0.0,
            "median_interval": 0.0,
            "interval_std": 0.0,
            "min_interval": 0.0,
            "max_interval": 0.0,
            "timing_regularity": 0.0,
            "unusual_timing": False,
            "night_activity_count": 0,
        }

    sorted_history = sorted(history, key=lambda item: item[0])
    intervals = [
        sorted_history[i + 1][0] - sorted_history[i][0]
        for i in range(len(sorted_history) - 1)
    ]

    avg_interval = sum(intervals) / len(intervals)
    median_interval = statistics.median(intervals)
    interval_std = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
    min_interval = min(intervals)
    max_interval = max(intervals)
    timing_regularity = 1.0 if avg_interval and interval_std <= max(1.0, avg_interval * 0.2) else 0.0
    unusual_timing = bool(len(intervals) >= 3 and timing_regularity > 0.0 and max_interval <= avg_interval * 2)

    night_activity_count = 0
    for ts, _ in sorted_history:
        dt = __import__("datetime").datetime.fromtimestamp(ts, tz=__import__("datetime").timezone.utc)
        if 0 <= dt.hour < 6:
            night_activity_count += 1

    return {
        "average_interval": round(avg_interval, 3),
        "median_interval": round(median_interval, 3),
        "interval_std": round(interval_std, 3),
        "min_interval": round(min_interval, 3),
        "max_interval": round(max_interval, 3),
        "timing_regularity": round(timing_regularity, 3),
        "unusual_timing": unusual_timing,
        "night_activity_count": int(night_activity_count),
    }


def compute_sudden_volume_change(history: List[Tuple[float, str]], now: Optional[float] = None) -> Dict[str, Any]:
    now = now if now is not None else time.time()
    if len(history) < 2:
        return {"sudden_volume_change": False, "change_ratio": 0.0}

    recent_5m = sum(1 for ts, _ in history if now - ts <= 5 * 60)
    recent_1h = sum(1 for ts, _ in history if now - ts <= 60 * 60)
    baseline = max(recent_1h - recent_5m, 1)
    ratio = recent_5m / baseline if baseline else 0.0

    return {
        "sudden_volume_change": recent_5m >= 3 and ratio >= 1.5,
        "change_ratio": round(ratio, 3),
    }


def compute_feature_vector(
    history: List[Tuple[float, str]],
    current_message: str,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    now = now if now is not None else time.time()

    frequency = compute_frequency_features(history, now=now)
    burst = detect_burst(history, now=now)
    repetition = compute_repetition_features(history, current_message)
    url_repetition = compute_url_repetition_features(history, current_message)
    timing = compute_timing_features(history)
    volume_change = compute_sudden_volume_change(history, now=now)

    feature_vector = {
        **frequency,
        "burst_detected": burst["burst_detected"],
        "burst_count": burst["burst_count"],
        "burst_window_seconds": burst["burst_window_seconds"],
        "messages_in_burst": burst["messages_in_burst"],
        "repeat_count": repetition["repeat_count"],
        "max_similarity": repetition["max_similarity"],
        "average_similarity": repetition["average_similarity"],
        "repeated_content": repetition["repeated_content"],
        "repeated_url": url_repetition["repeated_url"],
        "repeated_url_count": url_repetition["repeated_url_count"],
        "unique_url_count": url_repetition["unique_url_count"],
        "average_interval": timing["average_interval"],
        "median_interval": timing["median_interval"],
        "interval_std": timing["interval_std"],
        "min_interval": timing["min_interval"],
        "max_interval": timing["max_interval"],
        "timing_regularity": timing["timing_regularity"],
        "unusual_timing": timing["unusual_timing"],
        "sudden_volume_change": volume_change["sudden_volume_change"],
        "change_ratio": volume_change["change_ratio"],
    }

    return feature_vector
