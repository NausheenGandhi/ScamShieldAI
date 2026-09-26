"""
database/mongodb.py

Reusable MongoDB Atlas connection module.

- Reads connection settings from environment variables (never hard-code
  credentials).
- Opens ONE client for the process lifetime instead of a new connection
  per request.
- Fails soft: if MongoDB Atlas is unreachable, get_db() returns None and
  callers are expected to degrade gracefully rather than crash the app.

Env vars:

    MONGODB_URI        mongodb+srv://... (required)
    MONGODB_DATABASE   database name (default: "scamshield")
"""

import os
import time
import logging
import atexit
from typing import Optional

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import PyMongoError

logger = logging.getLogger("scamshield.mongodb")

_client: Optional[MongoClient] = None
_indexes_ready = False
_last_ping = 0.0

# Re-check the connection at most this often instead of on every get_db() call.
_PING_INTERVAL_SECONDS = 30


def get_client() -> Optional[MongoClient]:
    """Return the application-level MongoClient, creating it once per process."""
    return _get_client()


def close_mongo_client() -> None:
    """Close the shared MongoClient and reset index state so shutdown/tests can clean up safely."""
    global _client, _indexes_ready, _last_ping

    client = _client
    _client = None
    _indexes_ready = False
    _last_ping = 0.0

    if client is not None:
        try:
            client.close()
        except Exception:
            logger.exception("Error while closing MongoDB client")


# Ensure the MongoClient is closed on process exit to avoid ResourceWarning
atexit.register(close_mongo_client)


def _get_client() -> Optional[MongoClient]:
    global _client, _last_ping

    if _client is not None:
        if time.monotonic() - _last_ping < _PING_INTERVAL_SECONDS:
            return _client
        try:
            _client.admin.command("ping")
            _last_ping = time.monotonic()
            return _client
        except Exception:
            logger.warning("Existing MongoDB client is stale; reconnecting.")
            close_mongo_client()

    uri = os.environ.get("MONGODB_URI")

    if not uri:
        logger.warning(
            "MONGODB_URI is not set - MongoDB-backed features "
            "(sender reputation, message history) are disabled."
        )
        return None

    try:
        _client = MongoClient(
            uri,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
        )
        # Force a round trip so connection problems surface now, not on
        # first real query.
        _client.admin.command("ping")
        _last_ping = time.monotonic()

    except PyMongoError as e:
        logger.error("MongoDB connection failed: %s", str(e))
        close_mongo_client()

    return _client


def get_db():
    """Returns the configured database, or None if MongoDB is unavailable."""

    client = _get_client()

    if client is None:
        return None

    db_name = os.environ.get("MONGODB_DATABASE", "scamshield")
    return client[db_name]


# NOTE: these getters return raw collections. Application code should go through
# app.database.repository.secure_database_operation for message_records,
# spam_patterns, pattern_events and audit_logs. For real enforcement, give the
# app's Atlas user insert/find only on those collections (no update/delete).
def get_senders_collection():
    db = get_db()
    return db["senders"] if db is not None else None


def get_message_analyses_collection():
    db = get_db()
    return db["message_analyses"] if db is not None else None


def get_spam_patterns_collection():
    db = get_db()
    return db["spam_patterns"] if db is not None else None


def get_pattern_events_collection():
    db = get_db()
    return db["pattern_events"] if db is not None else None


def get_message_records_collection():
    db = get_db()
    return db["message_records"] if db is not None else None


def get_audit_logs_collection():
    db = get_db()
    return db["audit_logs"] if db is not None else None


def _unique_partial(field: str) -> dict:
    """Unique only for documents that have `field` (legacy documents without it are ignored)."""
    return {"unique": True, "partialFilterExpression": {field: {"$exists": True}}}


def ensure_indexes() -> None:
    """
    Idempotent - safe to call on every app startup. create_index() is a
    no-op if an equivalent index already exists.

    Needs index-creation privileges: run it with a setup credential, not the
    restricted application user.
    """

    global _indexes_ready

    if _indexes_ready:
        return

    db = get_db()

    if db is None:
        logger.warning("Skipping MongoDB index creation - no database connection.")
        return

    try:
        db["senders"].create_index(
            [("normalized_sender", ASCENDING)],
            unique=True,
            name="uniq_normalized_sender",
        )

        db["message_analyses"].create_index(
            [("sender", ASCENDING)],
            name="idx_sender",
        )

        db["message_analyses"].create_index(
            [("created_at", DESCENDING)],
            name="idx_created_at",
        )

        # --- message_records (hash-chained) ---
        db["message_records"].create_index(
            [("chain_seq", ASCENDING)],
            name="uniq_chain_seq",
            **_unique_partial("chain_seq"),
        )
        db["message_records"].create_index(
            [("message_id", ASCENDING)],
            name="uniq_message_id",
            **_unique_partial("message_id"),
        )
        db["message_records"].create_index(
            [("message_hash", ASCENDING)],
            name="idx_message_hash",
        )
        db["message_records"].create_index(
            [("timestamp", DESCENDING)],
            name="idx_message_timestamp",
        )

        # --- spam_patterns (hash-chained, immutable) ---
        db["spam_patterns"].create_index(
            [("chain_seq", ASCENDING)],
            name="uniq_chain_seq",
            **_unique_partial("chain_seq"),
        )
        db["spam_patterns"].create_index(
            [("pattern_id", ASCENDING)],
            name="uniq_pattern_id",
            **_unique_partial("pattern_id"),
        )
        db["spam_patterns"].create_index(
            [("representative_hash", ASCENDING)],
            unique=False,
            name="idx_spam_pattern_hash",
        )

        # --- pattern_events (append-only, hash-chained) ---
        db["pattern_events"].create_index(
            [("chain_seq", ASCENDING)],
            name="uniq_chain_seq",
            **_unique_partial("chain_seq"),
        )
        db["pattern_events"].create_index(
            [("event_id", ASCENDING)],
            name="uniq_event_id",
            **_unique_partial("event_id"),
        )
        db["pattern_events"].create_index(
            [("pattern_id", ASCENDING), ("record_type", ASCENDING)],
            name="idx_pattern_event_lookup",
        )

        # --- audit_logs (hash-chained) ---
        db["audit_logs"].create_index(
            [("chain_seq", ASCENDING)],
            name="uniq_chain_seq",
            **_unique_partial("chain_seq"),
        )
        db["audit_logs"].create_index(
            [("event_id", ASCENDING)],
            name="uniq_event_id",
            **_unique_partial("event_id"),
        )
        db["audit_logs"].create_index(
            [("event_type", ASCENDING)],
            name="idx_audit_event_type",
        )
        db["audit_logs"].create_index(
            [("timestamp", DESCENDING)],
            name="idx_audit_timestamp",
        )

        _indexes_ready = True
        logger.info("MongoDB indexes ready.")

    except PyMongoError as e:
        logger.error("MongoDB index creation failed: %s", str(e))


def is_available() -> bool:
    return _get_client() is not None