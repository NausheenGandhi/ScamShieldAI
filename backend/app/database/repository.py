from __future__ import annotations

import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from pymongo.errors import DuplicateKeyError

from app.database.mongodb import (
    get_audit_logs_collection,
    get_message_records_collection,
    get_pattern_events_collection,
    get_spam_patterns_collection,
)
from app.security.access_control import SecurityViolation, enforce_policy
from app.security.integrity import GENESIS_HASH, append_hash_chain

logger = logging.getLogger("scamshield.database.repository")

def _env_int(name: str, default: int) -> int:
    try:
        return int(float(os.environ.get(name, str(default))))
    except ValueError:
        return default


# Server-side policy (same env var the semantic service used before).
# Callers can no longer choose the threshold.
SPAM_CONFIRM_THRESHOLD = _env_int("SPAM_OCCURRENCE_THRESHOLD", 5)
MAX_APPEND_RETRIES = 5


class RepositorySecurityError(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_text(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def _new_id() -> str:
    return uuid.uuid4().hex


def _safe_resource_collection(resource: str):
    if resource == "message_records":
        return get_message_records_collection()
    if resource == "spam_patterns":
        return get_spam_patterns_collection()
    if resource == "audit_logs":
        return get_audit_logs_collection()
    return None


# ---------------------------------------------------------------------------
# Hash-chain append (safe head lookup + fork protection)
# ---------------------------------------------------------------------------
def _chain_head(collection) -> Tuple[int, str]:
    """Return (chain_seq, integrity_hash) of the newest chained record.

    Raises instead of silently restarting from GENESIS: a DB error must never
    reset the chain and hide a break.
    """
    try:
        last = collection.find_one(
            {"chain_seq": {"$exists": True}},
            sort=[("chain_seq", -1)],
        )
    except Exception as exc:
        raise RepositorySecurityError("Cannot read chain head.") from exc

    if last is None:
        return 0, GENESIS_HASH
    if not last.get("integrity_hash"):
        raise RepositorySecurityError("Chain head has no integrity_hash.")
    return int(last["chain_seq"]), last["integrity_hash"]


def _append_chained(collection, record_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Insert a hash-chained record. The unique index on chain_seq makes two
    concurrent writers unable to fork the chain; the loser retries."""
    for _ in range(MAX_APPEND_RETRIES):
        seq, previous_hash = _chain_head(collection)
        record = append_hash_chain(record_type, {**payload, "chain_seq": seq + 1}, previous_hash)
        try:
            result = collection.insert_one(record)
        except DuplicateKeyError as exc:
            key_pattern = (getattr(exc, "details", None) or {}).get("keyPattern") or {}
            if "chain_seq" in key_pattern:
                continue  # lost the race for this sequence number; re-read head and retry
            raise RepositorySecurityError("Duplicate record id.") from exc
        record["_id"] = str(result.inserted_id)
        return record
    raise RepositorySecurityError("Could not append to chain: too much write contention.")


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
def _write_audit(event_type: str, actor: str, resource_id: Optional[str], metadata: Dict[str, Any]) -> None:
    """Best-effort server-side audit entry. Never raises; never trusts client input for actor."""
    logs = get_audit_logs_collection()
    if logs is None:
        logger.error("Audit log unavailable; could not record %s", event_type)
        return
    try:
        _append_chained(
            logs,
            "AUDIT_EVENT",
            {
                "event_id": _new_id(),
                "event_type": event_type,
                "actor": actor,
                "resource_id": resource_id,
                "metadata": metadata,
            },
        )
    except Exception:
        logger.exception("Failed to write audit event %s", event_type)


# ---------------------------------------------------------------------------
# Record builders (server-generated IDs and hashes only)
# ---------------------------------------------------------------------------
def _message_payload(validated: Dict[str, Any], ts: str) -> Dict[str, Any]:
    body = str(validated.get("message_text") or validated.get("message_body") or "")
    return {
        "message_id": _new_id(),
        "message_hash": _hash_text(body),
        "semantic_group_id": validated.get("semantic_group_id"),
        "timestamp": ts,
        "classification": validated.get("classification", "UNKNOWN"),
        "risk_score": validated.get("risk_score", 0),
        "processing_path": validated.get("processing_path", "LANGGRAPH"),
        "metadata": validated.get("metadata", {}),
    }


def _pattern_payload(validated: Dict[str, Any], ts: str) -> Dict[str, Any]:
    message = str(validated.get("representative_message") or "")
    # No message_count / status here: they are derived from append-only events.
    return {
        "pattern_id": _new_id(),
        "representative_message": message,
        "representative_hash": _hash_text(message),
        "embedding": validated.get("embedding", []),
        "embedding_clean": validated.get("embedding_clean", []),
        "created_at": ts,
        "metadata": validated.get("metadata", {}),
    }


# ---------------------------------------------------------------------------
# Patterns: append-only events instead of in-place updates
# ---------------------------------------------------------------------------
def _find_pattern(patterns, validated: Dict[str, Any]) -> Dict[str, Any]:
    if validated.get("pattern_id"):
        query = {"pattern_id": validated["pattern_id"]}
    elif validated.get("representative_hash"):
        query = {"representative_hash": validated["representative_hash"]}
    else:
        raise RepositorySecurityError("pattern_id or representative_hash is required.")
    pattern = patterns.find_one(query, sort=[("chain_seq", 1)])
    if not pattern:
        raise RepositorySecurityError("Pattern not found.")
    return pattern


def get_pattern_state(pattern_id: str) -> Dict[str, Any]:
    """Derive message_count and status from events. Nothing is ever updated in place.

    message_count = 1 (the creating message) + number of PATTERN_MATCHED events
    status        = CONFIRMED_SPAM if a PATTERN_CONFIRMED event exists or the
                    count reaches the server-side threshold, else PENDING
    """
    patterns = get_spam_patterns_collection()
    events = get_pattern_events_collection()
    if patterns is None or events is None:
        raise RepositorySecurityError("MongoDB collections for patterns are unavailable.")
    if patterns.find_one({"pattern_id": pattern_id}, {"_id": 1}) is None:
        raise RepositorySecurityError("Pattern not found.")

    matches = events.count_documents({"pattern_id": pattern_id, "record_type": "PATTERN_MATCHED"})
    confirmed = events.count_documents({"pattern_id": pattern_id, "record_type": "PATTERN_CONFIRMED"}, limit=1) > 0
    count = 1 + matches
    status = "CONFIRMED_SPAM" if confirmed or count >= SPAM_CONFIRM_THRESHOLD else "PENDING"
    return {"pattern_id": pattern_id, "message_count": count, "status": status}


def _increment_pattern(patterns, validated: Dict[str, Any], actor: str) -> Dict[str, Any]:
    events = get_pattern_events_collection()
    if events is None:
        raise RepositorySecurityError("MongoDB collection 'pattern_events' is unavailable.")

    pattern = _find_pattern(patterns, validated)
    pattern_id = pattern["pattern_id"]
    message_id = validated.get("message_id")

    # Idempotent: the same message never counts twice for the same pattern.
    already = message_id and events.find_one(
        {"pattern_id": pattern_id, "record_type": "PATTERN_MATCHED", "message_id": message_id},
        {"_id": 1},
    )
    if not already:
        _append_chained(
            events,
            "PATTERN_MATCHED",
            {"event_id": _new_id(), "pattern_id": pattern_id, "message_id": message_id, "actor": actor},
        )

    state = get_pattern_state(pattern_id)
    logger.info("Pattern %s: message_count=%s status=%s", pattern_id, state["message_count"], state["status"])
    return state


def _confirm_spam(patterns, validated: Dict[str, Any], actor: str) -> Dict[str, Any]:
    events = get_pattern_events_collection()
    if events is None:
        raise RepositorySecurityError("MongoDB collection 'pattern_events' is unavailable.")

    pattern = _find_pattern(patterns, validated)
    pattern_id = pattern["pattern_id"]
    _append_chained(
        events,
        "PATTERN_CONFIRMED",
        {"event_id": _new_id(), "pattern_id": pattern_id, "actor": actor},
    )
    return get_pattern_state(pattern_id)


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------
def secure_database_operation(
    actor: str,
    operation: str,
    resource: str,
    data: Dict[str, Any],
    credential: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        decision = enforce_policy(actor, operation, resource, data or {}, credential)
    except SecurityViolation as exc:
        # Denied attempts leave a trace. The actor is unverified, so it is recorded
        # as metadata, never as the audit entry's actor.
        _write_audit(
            "ACCESS_DENIED",
            "UNVERIFIED",
            None,
            {
                "claimed_actor": str(actor)[:64],
                "operation": str(operation)[:64],
                "resource": str(resource)[:64],
                "reason": str(exc)[:200],
            },
        )
        raise

    op = decision.operation
    actor_name = decision.actor
    validated = decision.data

    collection = _safe_resource_collection(decision.resource)
    if collection is None:
        raise RepositorySecurityError(f"MongoDB collection for resource '{decision.resource}' is unavailable.")

    ts = _now().isoformat()

    if op == "CREATE_MESSAGE":
        result = _append_chained(collection, "MESSAGE_CREATED", _message_payload(validated, ts))
        resource_id = result["message_id"]

    elif op == "CREATE_PATTERN":
        result = _append_chained(collection, "PATTERN_CREATED", _pattern_payload(validated, ts))
        resource_id = result["pattern_id"]

    elif op == "CREATE_AUDIT_EVENT":
        # The actor is always the authenticated one, never a client-supplied value.
        return _append_chained(
            collection,
            "AUDIT_EVENT",
            {
                "event_id": _new_id(),
                "event_type": validated["event_type"],
                "actor": actor_name,
                "resource_id": validated.get("resource_id"),
                "metadata": validated.get("metadata", {}),
            },
        )

    elif op == "INCREMENT_PATTERN":
        result = _increment_pattern(collection, validated, actor_name)
        resource_id = result["pattern_id"]

    elif op == "CONFIRM_SPAM":
        result = _confirm_spam(collection, validated, actor_name)
        resource_id = result["pattern_id"]

    else:
        raise RepositorySecurityError(f"Unsupported operation '{op}' for repository security layer.")

    _write_audit(
        "OPERATION_EXECUTED",
        actor_name,
        resource_id,
        {"operation": op, "resource": decision.resource},
    )
    return result