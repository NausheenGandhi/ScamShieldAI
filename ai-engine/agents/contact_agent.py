"""
contact_agent.py

Contact Agent for SMS scam detection.

Original responsibilities (UNCHANGED):
    1. Take a device-computed signal for whether the sender is a saved
       contact (the backend cannot read the phone's address book itself).
    2. Track per-sender message history (frequency + content) to catch
       bursty / repeated spam campaigns - including from a saved contact
       whose phone or account may have been compromised and is now
       auto-blasting the same message to everyone in their contacts.
    3. Combine those signals into a CONTACT risk verdict.

Added responsibilities (this file's orchestration only - all new logic
lives in agents/contact/*):
    4. Classify the sender ID type (agents/contact/sender_classifier.py).
    5. Detect explainable message-content risk signals and classify the
       message as NORMAL/SUSPICIOUS/SPAM/SCAM (agents/contact/risk_analyzer.py).
    6. Detect brand impersonation (agents/contact/impersonation.py).
    7. Look up/update MongoDB Atlas sender reputation
       (agents/contact/reputation.py, database/mongodb.py).
    8. Combine everything into a single 0-100 trust score + verdict
       (agents/contact/trust_score.py).

Entry point: analyze_contact(...) -> dict

Backward compatibility: the function signature and the top-level
response fields (is_saved_contact, contact_name, level, score,
confidence, reasons, short_explanation, signals) are UNCHANGED so the
existing /analyze-contact endpoint in main.py and the existing
ContactAgentScreen.js UI keep working exactly as before. The full new
structured response (contact/sender/sender_reputation/message_analysis/
risk_signals/impersonation/trust) is added alongside it.
"""

import time
import threading
import difflib
import logging
from typing import Any, Dict, List, Optional, Tuple

from utils.groq_client import groq_chat
from prompts.contact_prompts import CONTACT_EXPLANATION_PROMPT

from .contact.sender_classifier import classify_sender
from .contact.risk_analyzer import detect_signals, get_classifier
from .contact.impersonation import detect_impersonation
from .contact.trust_score import calculate_trust_score
from .contact import reputation as contact_reputation

from app.database.mongodb import ensure_indexes

logger = logging.getLogger("scamshield.contact_agent")

try:
    ensure_indexes()
except Exception as e:  # pragma: no cover - defensive, must never block startup
    logger.warning("MongoDB index setup skipped: %s", str(e))


# ============================================================
# CONFIG (UNCHANGED)
# ============================================================

HISTORY_RETENTION_SECONDS = 24 * 60 * 60      # keep 24h of history per sender
BURST_WINDOW_SECONDS = 5 * 60                 # "burst" = N msgs within 5 min
BURST_MESSAGE_THRESHOLD = 3                   # >=3 msgs in the window => burst
SIMILARITY_THRESHOLD = 0.82                   # how close two messages must be to count as "the same"
MAX_HISTORY_PER_SENDER = 200                  # hard cap so memory can't grow unbounded


# ============================================================
# IN-MEMORY HISTORY STORE (UNCHANGED)
# ============================================================

class _ContactHistoryStore:
    def __init__(self):
        self._lock = threading.Lock()
        # normalized_sender -> list of (timestamp, message_text)
        self._history: Dict[str, List[Tuple[float, str]]] = {}

    def record_and_get(
        self,
        sender_key: str,
        message: str,
        now: Optional[float] = None,
    ) -> List[Tuple[float, str]]:
        """Adds this message to history, prunes old entries, and returns
        the sender's history *including* the message just added."""

        now = now if now is not None else time.time()

        with self._lock:
            entries = self._history.setdefault(sender_key, [])
            entries.append((now, message))

            cutoff = now - HISTORY_RETENTION_SECONDS
            entries[:] = [e for e in entries if e[0] >= cutoff]

            if len(entries) > MAX_HISTORY_PER_SENDER:
                del entries[: len(entries) - MAX_HISTORY_PER_SENDER]

            return list(entries)


_STORE = _ContactHistoryStore()


# ============================================================
# STEP 1: NORMALIZE SENDER (UNCHANGED)
# ============================================================

def normalize_sender(sender: str) -> str:
    """
    Collapses formatting differences (+91, spaces, dashes) so the same
    phone number is recognized as the same history key regardless of
    how it's written in a given SMS.
    """
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


# ============================================================
# STEP 2: FREQUENCY / BURST ANALYSIS (UNCHANGED)
# ============================================================

def analyze_frequency(
    history: List[Tuple[float, str]],
    now: Optional[float] = None,
) -> Dict[str, Any]:

    now = now if now is not None else time.time()

    count_5min = sum(1 for ts, _ in history if now - ts <= BURST_WINDOW_SECONDS)
    count_1hour = sum(1 for ts, _ in history if now - ts <= 60 * 60)
    count_24hour = len(history)

    burst_detected = count_5min >= BURST_MESSAGE_THRESHOLD

    return {
        "message_count_5min": count_5min,
        "message_count_1hour": count_1hour,
        "message_count_24hour": count_24hour,
        "burst_detected": burst_detected,
        "is_first_contact": count_24hour <= 1,
    }


# ============================================================
# STEP 3: CONTENT REPETITION ANALYSIS (UNCHANGED)
# ============================================================

def analyze_repetition(
    history: List[Tuple[float, str]],
    current_message: str,
) -> Dict[str, Any]:
    """
    Compares the current message against recent prior messages from the
    SAME sender. A near-identical message being resent repeatedly is a
    classic sign of an automated spam/scam blast - including from a
    friend's contact whose phone/account has been compromised.
    """

    past_messages = [m for _, m in history[:-1]]  # exclude the message just added

    if not past_messages or not current_message:
        return {"repeated_content": False, "repeat_count": 0, "max_similarity": 0.0}

    similarities = [
        difflib.SequenceMatcher(None, current_message.lower(), past.lower()).ratio()
        for past in past_messages
    ]

    max_similarity = max(similarities) if similarities else 0.0
    repeat_count = sum(1 for s in similarities if s >= SIMILARITY_THRESHOLD)

    return {
        "repeated_content": repeat_count >= 1,
        "repeat_count": repeat_count,
        "max_similarity": round(max_similarity, 2),
    }


# ============================================================
# STEP 4: LEGACY BURST/REPETITION RISK SCORING (UNCHANGED)
# ============================================================

def calculate_contact_risk(
    is_saved_contact: bool,
    frequency: Dict[str, Any],
    repetition: Dict[str, Any],
) -> Dict[str, Any]:

    score = 0
    reasons: List[str] = []

    burst_detected = frequency["burst_detected"]
    is_first_contact = frequency["is_first_contact"]
    message_count_1hour = frequency["message_count_1hour"]

    repeated_content = repetition["repeated_content"]

    # --------------------------------------------------------
    # Unknown sender
    # --------------------------------------------------------
    if not is_saved_contact:
        score += 2
        reasons.append("Sender is not in your saved contacts")

        if is_first_contact:
            score += 1
            reasons.append("This is the first message from this sender")

    # --------------------------------------------------------
    # Burst / high frequency
    # --------------------------------------------------------
    if burst_detected:
        score += 4
        reasons.append(
            f"{frequency['message_count_5min']} messages received from this "
            f"sender in the last 5 minutes"
        )
    elif message_count_1hour >= 5:
        score += 2
        reasons.append("Unusually high message frequency from this sender in the last hour")

    # --------------------------------------------------------
    # Repeated / near-identical content
    # --------------------------------------------------------
    if repeated_content:
        score += 4
        reasons.append("The same or very similar message has been sent repeatedly")

        # A KNOWN contact blasting repeated/identical messages is a strong
        # sign their account/device has been compromised, not a normal
        # conversation - so we weight this scenario a bit higher.
        if is_saved_contact:
            score += 2
            reasons.append(
                "This looks like automated spam from a saved contact - "
                "their phone or account may be compromised"
            )

    # --------------------------------------------------------
    # Trust note for a normal, low-frequency saved contact
    # --------------------------------------------------------
    if is_saved_contact and not burst_detected and not repeated_content:
        reasons.append("Message is from a saved contact with normal messaging patterns")

    # --------------------------------------------------------
    # Final level
    # --------------------------------------------------------
    if score >= 8:
        level = "DANGER"
    elif score >= 4:
        level = "CAUTION"
    else:
        level = "SAFE"

    confidence = min(50 + score * 6, 95)

    return {
        "level": level,
        "score": score,
        "confidence": confidence,
        "reasons": reasons,
    }


# ============================================================
# STEP 5: SHORT EXPLANATION (LLM, optional) (UNCHANGED)
# ============================================================

def generate_contact_explanation(
    level: str,
    reasons: List[str],
    contact_name: Optional[str],
) -> str:

    try:
        prompt = CONTACT_EXPLANATION_PROMPT.format(
            level=level,
            reasons="; ".join(reasons) if reasons else "No unusual signals detected.",
            contact_name=contact_name or "this sender",
        )

        return groq_chat(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=150,
        )

    except Exception as e:
        print("Contact explanation LLM call failed:", str(e))

        fallback = {
            "DANGER": "This sender's messaging pattern looks suspicious. Be cautious before responding or clicking anything.",
            "CAUTION": "Something about this sender's activity is a little unusual. Double-check before you act on this message.",
            "SAFE": "No unusual sender behavior detected.",
        }
        return fallback.get(level, fallback["SAFE"])


# ============================================================
# NEW HELPERS
# ============================================================

def _map_verdict_to_legacy_level(verdict: str) -> str:
    """
    Keeps the top-level "level" field compatible with the existing
    ContactAgentScreen.js UI, which only knows DANGER/CAUTION/SAFE.
    """
    return {
        "TRUSTED": "SAFE",
        "LOW_RISK": "SAFE",
        "CAUTION": "CAUTION",
        "SUSPICIOUS": "DANGER",
        "HIGH_RISK": "DANGER",
    }.get(verdict, "SAFE")


def _estimate_confidence(
    sender_doc: Dict[str, Any],
    signals: Dict[str, Any],
    frequency: Dict[str, Any],
    repetition: Dict[str, Any],
) -> int:
    confidence = 55

    if sender_doc.get("available"):
        confidence += 15
    if sender_doc.get("total_messages", 0) > 3:
        confidence += 10
    if frequency.get("burst_detected") or repetition.get("repeated_content"):
        confidence += 10
    if any([
        signals.get("financial_request"),
        signals.get("credential_request"),
        signals.get("threat"),
        signals.get("secrecy_request"),
    ]):
        confidence += 5

    return min(confidence, 95)


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


# ============================================================
# MAIN CONTACT AGENT
# ============================================================

def analyze_contact(
    sender: str,
    message: str,
    is_saved_contact: bool = False,
    contact_name: Optional[str] = None,
    timestamp: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Main entry point used by backend/main.py.

    Parameters (UNCHANGED - do not change this signature, main.py depends
    on it exactly as-is):
        sender             Raw SMS sender (phone number or short code).
        message            SMS body.
        is_saved_contact   Whether Android/RN found this number in the
                            device's contacts. MUST be computed on-device.
        contact_name       Saved contact's display name, if any.
        timestamp          Epoch seconds for this message (defaults to now).

    Returns:
        Backward-compatible top-level fields (is_saved_contact,
        contact_name, level, score, confidence, reasons,
        short_explanation, signals) PLUS the new structured response
        (contact, sender, sender_reputation, message_analysis,
        risk_signals, impersonation, trust).
    """

    now = timestamp if timestamp is not None else time.time()

    if not sender:
        sender = "unknown"
    if message is None:
        message = ""

    # ------------------------------------------------------------
    # 1-3. Sender history is kept for contact-level reputation tracking,
    #     but burst/repetition detection is owned by the Pattern Agent.
    # ------------------------------------------------------------
    history_key = normalize_sender(sender)
    history = _STORE.record_and_get(history_key, message, now=now)

    # ------------------------------------------------------------
    # 4. Sender ID type classification
    # ------------------------------------------------------------
    sender_classification = classify_sender(sender)
    mongo_sender_key = sender_classification.get("normalized") or history_key

    # ------------------------------------------------------------
    # 5. Message context signals + NORMAL/SUSPICIOUS/SPAM/SCAM
    # ------------------------------------------------------------
    signals = detect_signals(message)
    classification_result = get_classifier().classify(message, signals)

    # ------------------------------------------------------------
    # 6. Impersonation detection
    # ------------------------------------------------------------
    impersonation = detect_impersonation(message, sender_classification, signals)

    risk_signals = {
        "financial_request": signals["financial_request"],
        "credential_request": signals["credential_request"],
        "urgency": signals["urgency"],
        "threat": signals["threat"],
        "impersonation": impersonation["detected"],
        "suspicious_link": signals["suspicious_link"],
        "secrecy_request": signals["secrecy_request"],
    }

    # ------------------------------------------------------------
    # 7. MongoDB Atlas sender reputation (best-effort, never raises)
    # ------------------------------------------------------------
    is_suspicious_msg = classification_result["classification"] != "NORMAL"
    is_spam_msg = classification_result["classification"] in ("SPAM", "SCAM")

    sender_doc = contact_reputation.record_sender_activity(
        normalized_sender=mongo_sender_key,
        sender_type=sender_classification["sender_type"],
        is_suspicious=is_suspicious_msg,
        is_spam=is_spam_msg,
    )
    reputation_score = sender_doc.get("reputation_score", 50)
    reputation_status_label = contact_reputation.reputation_status(reputation_score)

    # ------------------------------------------------------------
    # 8. Trust score
    # ------------------------------------------------------------
    trust = calculate_trust_score(
        is_saved_contact=is_saved_contact,
        burst_detected=False,
        repeated_content=False,
        sender_type=sender_classification["sender_type"],
        sender_reputation_score=reputation_score,
        risk_signals=risk_signals,
        impersonation_risk=impersonation["risk"],
        spam_probability=classification_result["spam_probability"],
        scam_probability=classification_result["scam_probability"],
    )

    # Best-effort message history write (never blocks the response)
    contact_reputation.record_message_analysis(
        sender=mongo_sender_key,
        message=message,
        classification=classification_result["classification"],
        spam_probability=classification_result["spam_probability"],
        scam_probability=classification_result["scam_probability"],
        risk_signals=risk_signals,
        trust_score=trust["score"],
        verdict=trust["verdict"],
    )

    # ------------------------------------------------------------
    # Combined, de-duplicated human-readable reasons
    # ------------------------------------------------------------
    reasons: List[str] = []
    reasons.append(
        "Sender is saved in contacts." if is_saved_contact
        else "Sender is not in your saved contacts."
    )
    reasons.extend(signals["reasons"])
    if impersonation["detected"]:
        reasons.append(impersonation["reason"])
    if not any(risk_signals.values()):
        reasons.append("No significant scam indicators were detected.")
    reasons.append(
        f"Sender has a {reputation_status_label.replace('_', ' ').lower()} message history."
    )
    reasons = _dedupe_preserve_order(reasons)

    legacy_level = _map_verdict_to_legacy_level(trust["verdict"])
    confidence = _estimate_confidence(sender_doc, signals, {}, {})

    explanation = generate_contact_explanation(legacy_level, reasons, contact_name)

    return {
        # ------------------------------------------------------
        # Backward-compatible top-level fields
        # (relied on by main.py / ContactAgentScreen.js as-is)
        # ------------------------------------------------------
        "is_saved_contact": is_saved_contact,
        "contact_name": contact_name,

        "level": legacy_level,
        "score": trust["score"],
        "confidence": confidence,
        "reasons": reasons,

        "short_explanation": explanation,

        "signals": {
            "is_saved_contact": is_saved_contact,
            "is_first_contact": len(history) <= 1,
            "sender_type": sender_classification.get("sender_type"),
            "sender_reputation": reputation_status_label,
        },

        # ------------------------------------------------------
        # New structured response
        # ------------------------------------------------------
        "contact": {
            "is_saved_contact": is_saved_contact,
            "contact_name": contact_name,
        },
        "sender": {
            "normalized": sender_classification.get("normalized"),
            "type": sender_classification.get("sender_type"),
            "confidence": sender_classification.get("confidence"),
        },
        "sender_reputation": {
            "status": reputation_status_label,
            "spam_score": (100 - reputation_score) if sender_doc.get("available") else None,
            "total_messages": sender_doc.get("total_messages", 0),
            "suspicious_messages": sender_doc.get("suspicious_messages", 0),
            "spam_messages": sender_doc.get("spam_messages", 0),
            "mongo_available": sender_doc.get("available", False),
        },
        "message_analysis": {
            "classification": classification_result["classification"],
            "spam_probability": classification_result["spam_probability"],
            "scam_probability": classification_result["scam_probability"],
            "model_used": classification_result["model_used"],
        },
        "risk_signals": risk_signals,
        "impersonation": impersonation,
        "trust": {
            "score": trust["score"],
            "verdict": trust["verdict"],
            "components": trust["components"],
        },
    }