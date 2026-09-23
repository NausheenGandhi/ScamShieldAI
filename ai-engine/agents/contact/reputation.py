"""
agents/contact/reputation.py

MongoDB-backed sender reputation.

Every analyzed message upserts one document per normalized sender in the
`senders` collection (never duplicated - keyed on normalized_sender) and
inserts one document per message in `message_analyses`.

If MongoDB is unavailable, every function here degrades to a safe
"unknown history" result instead of raising - the Contact Agent must
keep working even when Atlas is down.
"""

import datetime
import hashlib
import logging
import os
import sys
from typing import Any, Dict, Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from pymongo import ReturnDocument
from pymongo.errors import PyMongoError

from app.database.mongodb import get_senders_collection, get_message_analyses_collection

logger = logging.getLogger("scamshield.contact.reputation")

# When false (default), message bodies are hashed rather than stored in
# plaintext in message_analyses. Flip on only for local debugging.
STORE_RAW_MESSAGE_BODY = os.environ.get("STORE_RAW_MESSAGE_BODY", "false").lower() == "true"


def _hash_message(message: str) -> str:
    return hashlib.sha256((message or "").encode("utf-8")).hexdigest()


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# ============================================================
# SENDER REPUTATION (upsert on every message)
# ============================================================

def record_sender_activity(
    normalized_sender: str,
    sender_type: str,
    is_suspicious: bool,
    is_spam: bool,
    now: Optional[datetime.datetime] = None,
) -> Dict[str, Any]:
    """
    Upserts the sender's reputation document and returns the up-to-date
    reputation snapshot. Never raises - returns a degraded/default
    snapshot if MongoDB is unavailable.
    """

    now = now or _now()

    default_snapshot = {
        "available": False,
        "sender": normalized_sender,
        "sender_type": sender_type,
        "total_messages": 1,
        "suspicious_messages": 1 if is_suspicious else 0,
        "spam_messages": 1 if is_spam else 0,
        "first_seen": now,
        "last_seen": now,
        "reputation_score": 50,  # neutral default - no history to judge from
    }

    collection = get_senders_collection()

    if collection is None:
        return default_snapshot

    try:
        update = {
            "$setOnInsert": {
                "sender": normalized_sender,
                "normalized_sender": normalized_sender,
                "first_seen": now,
            },
            "$set": {
                "sender_type": sender_type,
                "last_seen": now,
            },
            "$inc": {
                "total_messages": 1,
                "suspicious_messages": 1 if is_suspicious else 0,
                "spam_messages": 1 if is_spam else 0,
            },
        }

        doc = collection.find_one_and_update(
            {"normalized_sender": normalized_sender},
            update,
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )

        score = calculate_reputation_score(doc)

        collection.update_one(
            {"normalized_sender": normalized_sender},
            {"$set": {"reputation_score": score}},
        )

        doc["reputation_score"] = score
        doc["available"] = True

        return doc

    except PyMongoError as e:
        logger.error("Sender reputation upsert failed: %s", str(e))
        return default_snapshot


def calculate_reputation_score(sender_doc: Dict[str, Any]) -> int:
    """
    0-100, higher = better reputation. Combines message volume with the
    ratio of suspicious/spam messages so a single flagged message from a
    long, mostly-clean history doesn't tank the score permanently.
    """

    total = max(sender_doc.get("total_messages", 0), 1)
    suspicious = sender_doc.get("suspicious_messages", 0)
    spam = sender_doc.get("spam_messages", 0)

    suspicious_ratio = suspicious / total
    spam_ratio = spam / total

    score = 100
    score -= suspicious_ratio * 60
    score -= spam_ratio * 70

    # A brand-new sender with very little history gets a mild neutral
    # discount rather than full trust or full suspicion.
    if total <= 1:
        score = min(score, 65)

    return max(0, min(100, round(score)))


def reputation_status(score: int) -> str:
    if score >= 80:
        return "TRUSTED"
    if score >= 60:
        return "LOW_RISK"
    if score >= 40:
        return "CAUTION"
    if score >= 20:
        return "SUSPICIOUS"
    return "HIGH_RISK"


def get_sender_snapshot(normalized_sender: str) -> Dict[str, Any]:
    """Read-only lookup (not used by the main pipeline, kept as a utility)."""

    collection = get_senders_collection()

    if collection is None:
        return {"available": False, "total_messages": 0, "suspicious_messages": 0,
                "spam_messages": 0, "reputation_score": 50}

    try:
        doc = collection.find_one({"normalized_sender": normalized_sender})

        if not doc:
            return {"available": True, "total_messages": 0, "suspicious_messages": 0,
                    "spam_messages": 0, "reputation_score": 50}

        doc["available"] = True
        return doc

    except PyMongoError as e:
        logger.error("Sender reputation lookup failed: %s", str(e))
        return {"available": False, "total_messages": 0, "suspicious_messages": 0,
                "spam_messages": 0, "reputation_score": 50}


# ============================================================
# MESSAGE ANALYSIS HISTORY
# ============================================================

def record_message_analysis(
    sender: str,
    message: str,
    classification: str,
    spam_probability: float,
    scam_probability: float,
    risk_signals: Dict[str, bool],
    trust_score: int,
    verdict: str,
    now: Optional[datetime.datetime] = None,
) -> bool:
    """Best-effort write. Returns True if stored, False otherwise (never raises)."""

    now = now or _now()
    collection = get_message_analyses_collection()

    if collection is None:
        return False

    doc = {
        "sender": sender,
        "message_hash": _hash_message(message),
        "classification": classification,
        "spam_probability": round(spam_probability, 3),
        "scam_probability": round(scam_probability, 3),
        "risk_signals": risk_signals,
        "trust_score": trust_score,
        "verdict": verdict,
        "created_at": now,
    }

    if STORE_RAW_MESSAGE_BODY:
        doc["message_body"] = message

    try:
        collection.insert_one(doc)
        return True
    except PyMongoError as e:
        logger.error("Message analysis insert failed: %s", str(e))
        return False