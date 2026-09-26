import hashlib
import logging
import os
import re
from typing import Any, Dict, Optional

from app.database.mongodb import get_spam_patterns_collection
from app.database.repository import get_pattern_state, secure_database_operation
from app.services.embedding_service import generate_embedding

logger = logging.getLogger("scamshield.semantic")

# Lowered from 0.85: MiniLM scores paraphrased scam SMS well below 0.85.
DEFAULT_SIMILARITY_THRESHOLD = 0.70
# Token-overlap rescue window just below the similarity threshold.
FALLBACK_MARGIN = 0.05
FALLBACK_MIN_OVERLAP = 3

# The number of matches that confirms a pattern as spam (SPAM_OCCURRENCE_THRESHOLD,
# default 5) is now decided server-side inside the repository, not passed by this service.

APP_ACTOR = "APPLICATION_SERVICE"
_missing_secret_logged = False

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
# Matches http://x, https://x, malformed "https:x", and www.x
_URL_RE = re.compile(r"\b(?:https?:?/*|www\.)\S+", re.I)
# Bare domains such as bity.in/ or bank.com/kyc
_BARE_DOMAIN_RE = re.compile(
    r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|net|org|co|io|ly|me|xyz|top|info|online|site|link)\b\S*",
    re.I,
)
# Greeting / attention boilerplate that varies between otherwise identical scams
_BOILERPLATE_RE = re.compile(r"\b(?:dear customer|dear user|dear sir|urgent|alert)\b[:,]?", re.I)
_PUNCT_RE = re.compile(r"[^a-z0-9\s]")
_WS_RE = re.compile(r"\s+")

_STOPWORDS = {
    "the", "and", "is", "in", "on", "for", "a", "an", "to", "your", "please", "now", "will",
}


def _get_threshold(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return default


def _hash_text(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def _normalize_for_embedding(text: str) -> str:
    """Remove URLs (including malformed ones), bare domains and boilerplate; lowercase; collapse whitespace."""
    if not text:
        return ""
    try:
        text = _URL_RE.sub(" ", text)
        text = _BARE_DOMAIN_RE.sub(" ", text)
        text = _BOILERPLATE_RE.sub(" ", text)
        return _WS_RE.sub(" ", text).strip().lower()
    except Exception:
        return (text or "").strip().lower()


def _token_set(text: str) -> set:
    """Set of normalized tokens excluding simple stopwords."""
    try:
        s = _PUNCT_RE.sub(" ", _normalize_for_embedding(text))
        return {tok for tok in s.split() if len(tok) > 1 and tok not in _STOPWORDS}
    except Exception:
        return set()


def _semantic_similarity(a: list, b: list) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def _safe_embedding(text: str) -> list:
    try:
        # Plain Python floats: the security layer only accepts finite int/float values
        # (numpy float32 values would be rejected).
        return [float(x) for x in generate_embedding(text)]
    except Exception as exc:
        logger.warning("Embedding generation failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Pattern lookup
# ---------------------------------------------------------------------------
def _find_best_pattern(message: str, embedding: list) -> Optional[Dict[str, Any]]:
    collection = get_spam_patterns_collection()
    if collection is None:
        logger.warning("[semantic_search] 'spam_patterns' collection unavailable.")
        return None

    try:
        docs = list(collection.find({}))
    except Exception as exc:
        logger.warning("[semantic_search] MongoDB query failed: %s", exc)
        return None

    print(f"[semantic_search] candidate_count={len(docs)}")

    best_doc = None
    best_score = -1.0
    for doc in docs:
        doc_id = doc.get("pattern_id") or str(doc.get("_id"))

        emb_to_compare = doc.get("embedding_clean")
        source = "embedding_clean"
        if not emb_to_compare:
            # Legacy docs: embed the cleaned representative message on the fly.
            rep_msg = doc.get("representative_message") or ""
            if not rep_msg:
                print(f"[semantic_search] skipping doc {doc_id}: no representative_message")
                continue
            emb_to_compare = _safe_embedding(_normalize_for_embedding(rep_msg))
            source = "computed_cleaned_embedding"

        if not emb_to_compare:
            print(f"[semantic_search] skipping doc {doc_id}: no embedding to compare")
            continue

        score = _semantic_similarity(embedding, emb_to_compare)
        print(f"[semantic_search] doc {doc_id[:12]}: source={source}, len={len(emb_to_compare)}, similarity={score:.4f}")
        if score > best_score:
            best_score = score
            best_doc = doc

    if best_doc is None:
        print("[semantic_search] no candidate matched")
        return None

    best_doc["_similarity"] = best_score
    return best_doc


def _get_pattern_state_safe(pattern_id: str) -> Dict[str, Any]:
    """
    Wraps get_pattern_state() so a MongoDB hiccup degrades to a safe,
    conservative default (count=1, PENDING) instead of raising and
    breaking the fast-path response.
    """
    try:
        return get_pattern_state(str(pattern_id))
    except Exception as exc:
        logger.warning("Could not read pattern state for %s: %s", pattern_id, exc)
        return {"pattern_id": pattern_id, "message_count": 1, "status": "PENDING"}


def _get_pattern_status(pattern_id: str) -> str:
    """Status is derived from the append-only event log, not stored on the pattern."""
    return _get_pattern_state_safe(pattern_id).get("status", "PENDING")


def _build_spam_reason(report_count: int) -> str:
    """
    Plain-language explanation for the UI: why this message was flagged
    without going through the agent pipeline, plus the crowd-sourced
    report count so the user has something concrete to weigh.
    """
    times_word = "time" if report_count == 1 else "times"
    return (
        f"This message matches a pattern that has already been confirmed as "
        f"spam. It has been seen {report_count} {times_word} across "
        f"messages sent to users of this app."
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def _create_new_pattern(clean_message: str, embedding: list, embedding_clean: list, sender: str) -> None:
    _persist_pattern({
        "representative_message": clean_message,
        "embedding": embedding,
        "embedding_clean": embedding_clean,
        "metadata": {"source_sender": sender},
    })


def semantic_precheck(message: str, sender: str = "unknown") -> Dict[str, Any]:
    clean_message = (message or "").strip()
    threshold = _get_threshold("SEMANTIC_SIMILARITY_THRESHOLD", DEFAULT_SIMILARITY_THRESHOLD)

    if not clean_message:
        return {"should_continue": True, "processing_path": "LANGGRAPH", "reason": "empty-message"}

    incoming_for_match = _normalize_for_embedding(clean_message)
    embedding = _safe_embedding(clean_message)
    embedding_clean = _safe_embedding(incoming_for_match)

    print("[semantic_precheck] incoming message:", clean_message)
    print("[semantic_precheck] cleaned message:", incoming_for_match)
    print("[semantic_precheck] embedding_dim:", len(embedding), "cleaned_dim:", len(embedding_clean))

    pattern = _find_best_pattern(clean_message, embedding_clean)

    if pattern is None:
        print("[semantic_precheck] best matching pattern_id: None (no match)")
        _create_new_pattern(clean_message, embedding, embedding_clean, sender)
        return {
            "should_continue": True,
            "processing_path": "LANGGRAPH",
            "pattern_status": "PENDING",
            "matched": False,
            "similarity": 0.0,
        }

    pattern_id = str(pattern.get("pattern_id") or pattern.get("_id"))
    similarity = float(pattern.get("_similarity", 0.0))

    try:
        rep_msg = str(pattern.get("representative_message") or "")
        overlap = len(_token_set(incoming_for_match) & _token_set(rep_msg))
    except Exception:
        overlap = 0

    print("[semantic_precheck] best matching pattern_id:", pattern_id)
    print("[semantic_precheck] cosine similarity score:", similarity)
    print(f"[semantic_precheck] configured similarity threshold: {threshold}")
    print("[semantic_precheck] token_overlap_with_best_pattern:", overlap)

    is_match = similarity >= threshold
    is_fallback_match = (
        not is_match
        and similarity >= (threshold - FALLBACK_MARGIN)
        and overlap >= FALLBACK_MIN_OVERLAP
    )
    print("[semantic_precheck] considered_match:", is_match or is_fallback_match)

    # ---- No match: start a new pattern -----------------------------------
    if not (is_match or is_fallback_match):
        _create_new_pattern(clean_message, embedding, embedding_clean, sender)
        return {
            "should_continue": True,
            "processing_path": "LANGGRAPH",
            "pattern_status": "PENDING",
            "matched": False,
            "similarity": similarity,
        }

    # Current status + count, derived from the pattern's event log.
    pattern_state = _get_pattern_state_safe(pattern_id)
    pattern_status = pattern_state.get("status", "PENDING")
    report_count = pattern_state.get("message_count", 1)

    # ---- Already confirmed spam: fast path (exact-threshold matches only) --
    if is_match and pattern_status == "CONFIRMED_SPAM":
        reason = _build_spam_reason(report_count)
        _persist_message({
            "message_text": clean_message,
            "semantic_group_id": pattern_id,
            "classification": "SPAM",
            "risk_score": 100,
            "processing_path": "SEMANTIC_FAST_PATH",
            "metadata": {"pattern_status": "CONFIRMED_SPAM", "similarity": similarity, "sender": sender},
        })
        return {
            "should_continue": False,
            "processing_path": "SEMANTIC_FAST_PATH",
            "matched": True,
            "fast_path_spam": True,
            "similarity": similarity,
            "classification": "SPAM",
            "risk_score": 100,
            "pattern_status": "CONFIRMED_SPAM",
            "pattern_id": pattern_id,
            "report_count": report_count,
            "reason": reason,
        }

    # ---- Match (normal or fallback): record the match and use the fresh status ----
    inc = _increment_pattern(pattern_id)
    new_status = inc.get("status", pattern_status)
    new_count = inc.get("message_count", report_count)

    _persist_message({
        "message_text": clean_message,
        "semantic_group_id": pattern_id,
        "classification": "PENDING",
        "risk_score": 50,
        "processing_path": "LANGGRAPH",
        "metadata": {
            "pattern_status": new_status,
            "similarity": similarity,
            "sender": sender,
            "fallback_match": is_fallback_match,
        },
    })

    result = {
        "should_continue": True,
        "processing_path": "LANGGRAPH",
        "pattern_status": new_status,
        "matched": True,
        "similarity": similarity,
        "pattern_id": pattern_id,
        "report_count": new_count,
    }
    if new_status == "CONFIRMED_SPAM":
        result["classification"] = "SPAM"
        result["risk_score"] = 100
        result["reason"] = _build_spam_reason(new_count)
    elif is_fallback_match:
        result["classification"] = "PENDING"
    return result


# ---------------------------------------------------------------------------
# Persistence helpers (all writes go through the security layer)
# ---------------------------------------------------------------------------
def _credential() -> Optional[str]:
    global _missing_secret_logged
    secret = os.environ.get(f"ACTOR_SECRET_{APP_ACTOR}")
    if not secret and not _missing_secret_logged:
        logger.error(
            "ACTOR_SECRET_%s is not set: every database write will be rejected by the security layer.",
            APP_ACTOR,
        )
        _missing_secret_logged = True
    return secret


def _secure(operation: str, resource: str, data: Dict[str, Any]) -> Dict[str, Any]:
    return secure_database_operation(
        actor=APP_ACTOR,
        operation=operation,
        resource=resource,
        data=data,
        credential=_credential(),
    )


def _persist_pattern(data: Dict[str, Any]) -> None:
    try:
        _secure("CREATE_PATTERN", "spam_patterns", data)
    except Exception as exc:
        logger.warning("Semantic pattern persistence unavailable: %s", exc)


def _persist_message(data: Dict[str, Any]) -> None:
    try:
        _secure("CREATE_MESSAGE", "message_records", data)
    except Exception as exc:
        logger.warning("Message record persistence unavailable: %s", exc)


def _increment_pattern(pattern_id: str) -> Dict[str, Any]:
    try:
        return _secure("INCREMENT_PATTERN", "spam_patterns", {"pattern_id": str(pattern_id)})
    except Exception as exc:
        logger.warning("Pattern increment unavailable: %s", exc)
        return {"pattern_id": str(pattern_id), "status": "PENDING"}


def _confirm_spam(pattern_id: str) -> Dict[str, Any]:
    try:
        return _secure("CONFIRM_SPAM", "spam_patterns", {"pattern_id": str(pattern_id)})
    except Exception as exc:
        logger.warning("Spam confirmation unavailable: %s", exc)
        return {"pattern_id": str(pattern_id), "status": "CONFIRMED_SPAM"}