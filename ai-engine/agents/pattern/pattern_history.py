import hashlib
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.database.mongodb import get_message_analyses_collection

HISTORY_RETENTION_SECONDS = 24 * 60 * 60
MAX_HISTORY_PER_SENDER = 500


def normalize_sender(sender: str) -> str:
    if not sender:
        return "unknown"

    cleaned = (
        sender.replace("+", "")
        .replace("-", "")
        .replace(" ", "")
        .replace("(", "")
        .replace(")", "")
    )
    return cleaned or "unknown"


def _hash_message(message: str) -> str:
    return hashlib.sha256((message or "").encode("utf-8")).hexdigest()


class PatternHistoryStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._history: Dict[str, List[Tuple[float, str]]] = defaultdict(list)

    def record_and_get(
        self,
        sender_key: str,
        message: str,
        now: Optional[float] = None,
    ) -> List[Tuple[float, str]]:
        now = now if now is not None else time.time()

        with self._lock:
            entries = self._history.setdefault(sender_key, [])
            entries.append((now, message or ""))

            cutoff = now - HISTORY_RETENTION_SECONDS
            entries[:] = [entry for entry in entries if entry[0] >= cutoff]

            if len(entries) > MAX_HISTORY_PER_SENDER:
                del entries[: len(entries) - MAX_HISTORY_PER_SENDER]

            return list(entries)

    def get_recent_entries(
        self,
        sender_key: str,
        now: Optional[float] = None,
        max_age_seconds: int = HISTORY_RETENTION_SECONDS,
    ) -> List[Tuple[float, str]]:
        now = now if now is not None else time.time()
        with self._lock:
            entries = self._history.get(sender_key, [])
            cutoff = now - max_age_seconds
            return [entry for entry in entries if entry[0] >= cutoff]


_PATTERN_STORE = PatternHistoryStore()


def get_pattern_history(sender: str, timestamp: Optional[float] = None) -> List[Tuple[float, str]]:
    sender_key = normalize_sender(sender)
    now = timestamp if timestamp is not None else time.time()
    return _PATTERN_STORE.get_recent_entries(sender_key, now=now)


def record_pattern_message(sender: str, message: str, timestamp: Optional[float] = None) -> List[Tuple[float, str]]:
    sender_key = normalize_sender(sender)
    return _PATTERN_STORE.record_and_get(sender_key, message, now=timestamp)


def get_sender_mongo_history(sender: str, hours: int = 24) -> Dict[str, Any]:
    collection = get_message_analyses_collection()
    normalized_sender = normalize_sender(sender)

    if collection is None:
        return {
            "available": False,
            "count": 0,
            "message_hashes": [],
            "last_seen": None,
        }

    cutoff = datetime.now(timezone.utc) - __import__("datetime").timedelta(hours=hours)

    try:
        docs = list(
            collection.find(
                {"sender": normalized_sender, "created_at": {"$gte": cutoff}},
                {"message_hash": 1, "created_at": 1},
            ).sort("created_at", -1).limit(200)
        )
        return {
            "available": True,
            "count": len(docs),
            "message_hashes": [doc.get("message_hash") for doc in docs if doc.get("message_hash")],
            "last_seen": docs[0].get("created_at") if docs else None,
        }
    except Exception:
        return {
            "available": False,
            "count": 0,
            "message_hashes": [],
            "last_seen": None,
        }
