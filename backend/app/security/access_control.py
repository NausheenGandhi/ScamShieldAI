import hmac
import logging
import math
import os
import re
from typing import Any, Dict, NamedTuple

from .hashing import canonical_json

logger = logging.getLogger("scamshield.security.access")

# ---------------------------------------------------------------------------
# Limits / allowed values. Adjust the classification labels and score range to
# whatever your pipeline actually produces.
# ---------------------------------------------------------------------------
MAX_TEXT_CHARS = 10_000
MAX_ID_CHARS = 128
MAX_METADATA_BYTES = 16_384
MAX_EMBEDDING_DIM = 4096
RISK_SCORE_MIN = 0
RISK_SCORE_MAX = 100
ALLOWED_CLASSIFICATIONS = {"SPAM", "SCAM", "PHISHING", "SUSPICIOUS", "SAFE", "HAM", "PENDING", "UNKNOWN"}
ALLOWED_PROCESSING_PATHS = {"LANGGRAPH", "SEMANTIC_FAST_PATH"}

# Event types only the server may write (ACCESS_DENIED / OPERATION_EXECUTED).
RESERVED_EVENT_TYPES = {"ACCESS_DENIED", "OPERATION_EXECUTED"}

_EVENT_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_ACTOR_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

ALLOWED_OPERATIONS = {
    "CREATE_MESSAGE": {"APPLICATION_SERVICE", "ADMINISTRATOR", "AUDIT_SECURITY_SERVICE"},
    "CREATE_PATTERN": {"APPLICATION_SERVICE", "ADMINISTRATOR"},
    "INCREMENT_PATTERN": {"APPLICATION_SERVICE", "ADMINISTRATOR"},
    "CONFIRM_SPAM": {"APPLICATION_SERVICE", "ADMINISTRATOR"},
    "CREATE_AUDIT_EVENT": {"APPLICATION_SERVICE", "AUDIT_SECURITY_SERVICE", "ADMINISTRATOR"},
    "UPDATE_HISTORY": set(),
    "DELETE_HISTORY": set(),
    "CHANGE_MESSAGE_HASH": set(),
    "CHANGE_OLD_VERDICT": set(),
    "CHANGE_TIMESTAMP": set(),
    "CHANGE_PREVIOUS_HASH": set(),
    "READ_MESSAGE": {"APPLICATION_SERVICE", "ADMINISTRATOR", "AUDIT_SECURITY_SERVICE"},
    "READ_PATTERN": {"APPLICATION_SERVICE", "ADMINISTRATOR", "AUDIT_SECURITY_SERVICE"},
}

BLOCKED_OPERATIONS = {
    "UPDATE_HISTORY",
    "DELETE_HISTORY",
    "CHANGE_MESSAGE_HASH",
    "CHANGE_OLD_VERDICT",
    "CHANGE_TIMESTAMP",
    "CHANGE_PREVIOUS_HASH",
}

# Which resource each operation may target. Prevents e.g. CREATE_MESSAGE on spam_patterns.
OPERATION_RESOURCES = {
    "CREATE_MESSAGE": {"message_records"},
    "CREATE_PATTERN": {"spam_patterns"},
    "INCREMENT_PATTERN": {"spam_patterns"},
    "CONFIRM_SPAM": {"spam_patterns"},
    "CREATE_AUDIT_EVENT": {"audit_logs"},
    "READ_MESSAGE": {"message_records"},
    "READ_PATTERN": {"spam_patterns"},
}

# Whitelist of client-supplied fields per operation. Anything else is rejected.
# IDs (message_id, pattern_id for creation, event_id) are always server-generated.
OPERATION_FIELDS = {
    "CREATE_MESSAGE": {"message_text", "message_body", "classification", "risk_score", "semantic_group_id", "processing_path", "metadata"},
    "CREATE_PATTERN": {"representative_message", "embedding", "embedding_clean", "metadata"},
    "INCREMENT_PATTERN": {"pattern_id", "representative_hash", "message_id"},
    "CONFIRM_SPAM": {"pattern_id"},
    "CREATE_AUDIT_EVENT": {"event_type", "resource_id", "metadata"},
    "READ_MESSAGE": {"message_id"},
    "READ_PATTERN": {"pattern_id"},
}

PROTECTED_RESOURCES = {
    "message_records",
    "spam_patterns",
    "audit_logs",
    "message_analyses",
    "senders",
}

FORBIDDEN_WRITE_FIELDS = {
    "message_count",
    "status",
    "previous_hash",
    "integrity_hash",
    "chain_seq",
    "timestamp",
    "created_at",
    "updated_at",
    "message_hash",
    "record_id",
    "actor",
    "id",
    "_id",
}


class SecurityViolation(RuntimeError):
    pass


class AuthorizationError(SecurityViolation):
    pass


class PolicyDecision(NamedTuple):
    actor: str
    operation: str
    resource: str
    data: Dict[str, Any]


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
def authenticate_actor(actor: str, credential: str = None) -> str:
    """Verify the caller's credential and return the normalized actor name.

    Each actor's secret is read from the environment variable
    ACTOR_SECRET_<ACTOR>, e.g. ACTOR_SECRET_APPLICATION_SERVICE.
    An actor with no configured secret cannot authenticate (fail closed).
    """
    if actor is None or not str(actor).strip():
        raise AuthorizationError("Actor is required.")
    actor_name = str(actor).strip().upper()
    if not _ACTOR_RE.match(actor_name):
        raise AuthorizationError("Authentication failed.")

    expected = os.environ.get(f"ACTOR_SECRET_{actor_name}")
    if not expected or not credential:
        raise AuthorizationError("Authentication failed.")
    if not hmac.compare_digest(str(credential).encode("utf-8"), expected.encode("utf-8")):
        raise AuthorizationError("Authentication failed.")
    return actor_name


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------
def authorize_operation(actor: str, operation: str, resource: str, credential: str = None) -> str:
    """Authenticate, then authorize. Returns the authenticated actor name."""
    actor_name = authenticate_actor(actor, credential)
    op_name = str(operation).strip().upper()
    resource_name = str(resource).strip().lower()

    if op_name not in ALLOWED_OPERATIONS:
        raise AuthorizationError(f"Operation '{operation}' is not recognized.")
    if op_name in BLOCKED_OPERATIONS:
        raise AuthorizationError(f"Operation '{operation}' is blocked by policy.")
    if resource_name not in OPERATION_RESOURCES.get(op_name, set()):
        raise AuthorizationError(f"Operation '{op_name}' is not permitted on resource '{resource_name}'.")
    if actor_name not in ALLOWED_OPERATIONS[op_name]:
        raise AuthorizationError(
            f"Actor '{actor_name}' is not authorized for operation '{op_name}' on resource '{resource_name}'."
        )
    return actor_name


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _check_text(name: str, value: Any, max_len: int) -> None:
    if not isinstance(value, str):
        raise SecurityViolation(f"'{name}' must be a string.")
    if len(value) > max_len:
        raise SecurityViolation(f"'{name}' is too long (max {max_len} characters).")


def _check_metadata(value: Any) -> None:
    if not isinstance(value, dict):
        raise SecurityViolation("'metadata' must be an object.")
    try:
        size = len(canonical_json(value).encode("utf-8"))
    except (TypeError, ValueError):
        raise SecurityViolation("'metadata' must be JSON-serializable.")
    if size > MAX_METADATA_BYTES:
        raise SecurityViolation(f"'metadata' is too large (max {MAX_METADATA_BYTES} bytes).")


def _check_vector(name: str, value: Any) -> None:
    if not isinstance(value, list):
        raise SecurityViolation(f"'{name}' must be a list of numbers.")
    if len(value) > MAX_EMBEDDING_DIM:
        raise SecurityViolation(f"'{name}' has too many dimensions (max {MAX_EMBEDDING_DIM}).")
    if not all(_is_number(x) for x in value):
        raise SecurityViolation(f"'{name}' must contain only finite numbers.")


def _validate_fields(op: str, safe: Dict[str, Any]) -> None:
    if op == "CREATE_MESSAGE":
        body = safe.get("message_text", safe.get("message_body"))
        if body is None:
            raise SecurityViolation("'message_text' is required.")
        _check_text("message_text", body, MAX_TEXT_CHARS)
        if "classification" in safe:
            _check_text("classification", safe["classification"], 32)
            label = safe["classification"].strip().upper()
            if label not in ALLOWED_CLASSIFICATIONS:
                raise SecurityViolation(f"'classification' must be one of {sorted(ALLOWED_CLASSIFICATIONS)}.")
            safe["classification"] = label
        if "risk_score" in safe:
            score = safe["risk_score"]
            if not _is_number(score) or not (RISK_SCORE_MIN <= score <= RISK_SCORE_MAX):
                raise SecurityViolation(f"'risk_score' must be a number between {RISK_SCORE_MIN} and {RISK_SCORE_MAX}.")
        if safe.get("semantic_group_id") is not None:
            _check_text("semantic_group_id", safe["semantic_group_id"], MAX_ID_CHARS)
        if "processing_path" in safe and safe["processing_path"] not in ALLOWED_PROCESSING_PATHS:
            raise SecurityViolation(f"'processing_path' must be one of {sorted(ALLOWED_PROCESSING_PATHS)}.")
        if "metadata" in safe:
            _check_metadata(safe["metadata"])

    elif op == "CREATE_PATTERN":
        message = safe.get("representative_message")
        if not isinstance(message, str) or not message.strip():
            raise SecurityViolation("'representative_message' is required.")
        _check_text("representative_message", message, MAX_TEXT_CHARS)
        for name in ("embedding", "embedding_clean"):
            if name in safe:
                _check_vector(name, safe[name])
        if "metadata" in safe:
            _check_metadata(safe["metadata"])

    elif op == "INCREMENT_PATTERN":
        if not safe.get("pattern_id") and not safe.get("representative_hash"):
            raise SecurityViolation("'pattern_id' or 'representative_hash' is required.")
        for name in ("pattern_id", "representative_hash", "message_id"):
            if safe.get(name) is not None:
                _check_text(name, safe[name], MAX_ID_CHARS)

    elif op == "CONFIRM_SPAM":
        if not safe.get("pattern_id"):
            raise SecurityViolation("'pattern_id' is required.")
        _check_text("pattern_id", safe["pattern_id"], MAX_ID_CHARS)

    elif op == "CREATE_AUDIT_EVENT":
        event_type = safe.get("event_type")
        if not isinstance(event_type, str) or not _EVENT_TYPE_RE.match(event_type):
            raise SecurityViolation("'event_type' must be UPPER_SNAKE_CASE (max 64 characters).")
        if event_type in RESERVED_EVENT_TYPES:
            raise SecurityViolation(f"Event type '{event_type}' is reserved for the server.")
        if safe.get("resource_id") is not None:
            _check_text("resource_id", safe["resource_id"], MAX_ID_CHARS)
        if "metadata" in safe:
            _check_metadata(safe["metadata"])

    elif op in {"READ_MESSAGE", "READ_PATTERN"}:
        for name, value in safe.items():
            _check_text(name, value, MAX_ID_CHARS)


def validate_request_data(operation: str, resource: str, data: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise SecurityViolation("Database payload must be a dictionary.")
    op = str(operation).strip().upper()

    blocked = sorted(name for name in FORBIDDEN_WRITE_FIELDS if name in data)
    if blocked:
        raise SecurityViolation(
            f"Forbidden write fields for {resource}: {', '.join(blocked)}. Those values are server-generated."
        )

    unknown = sorted(set(data) - OPERATION_FIELDS.get(op, set()))
    if unknown:
        raise SecurityViolation(f"Fields not accepted for {op}: {', '.join(map(str, unknown))}.")

    safe = dict(data)
    _validate_fields(op, safe)
    return safe


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------
def enforce_policy(actor: str, operation: str, resource: str, data: Dict[str, Any], credential: str = None) -> PolicyDecision:
    """Authenticate, authorize and validate. Returns the authenticated actor and clean data."""
    actor_name = authorize_operation(actor, operation, resource, credential)
    op = str(operation).strip().upper()
    res = str(resource).strip().lower()
    safe = validate_request_data(op, res, data)
    return PolicyDecision(actor_name, op, res, safe)


def validate_operation_policy(actor: str, operation: str, resource: str, data: Dict[str, Any], credential: str = None) -> Dict[str, Any]:
    return enforce_policy(actor, operation, resource, data, credential).data