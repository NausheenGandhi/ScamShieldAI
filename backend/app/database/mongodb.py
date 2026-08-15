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
import logging
from typing import Optional

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import PyMongoError

logger = logging.getLogger("scamshield.mongodb")

_client: Optional[MongoClient] = None
_indexes_ready = False


def _get_client() -> Optional[MongoClient]:
    global _client

    if _client is not None:
        return _client

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

    except PyMongoError as e:
        logger.error("MongoDB connection failed: %s", str(e))
        _client = None

    return _client


def get_db():
    """Returns the configured database, or None if MongoDB is unavailable."""

    client = _get_client()

    if client is None:
        return None

    db_name = os.environ.get("MONGODB_DATABASE", "scamshield")
    return client[db_name]


def get_senders_collection():
    db = get_db()
    return db["senders"] if db is not None else None


def get_message_analyses_collection():
    db = get_db()
    return db["message_analyses"] if db is not None else None


def ensure_indexes() -> None:
    """
    Idempotent - safe to call on every app startup. create_index() is a
    no-op if an equivalent index already exists.
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

        _indexes_ready = True
        logger.info("MongoDB indexes ready.")

    except PyMongoError as e:
        logger.error("MongoDB index creation failed: %s", str(e))


def is_available() -> bool:
    return _get_client() is not None