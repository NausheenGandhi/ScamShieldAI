"""
Checks the security layer against a REAL Atlas database.

Run from the backend folder:

    python scripts/check_atlas.py             # create records, verify the chain
    python scripts/check_atlas.py --tamper    # also edit a record by hand, show it is detected, then restore it

Safety: refuses to run unless MONGODB_DATABASE contains "test".
Passwords and keys are never printed.
"""
import logging
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv

    # Looks in backend/.env and backend/app/.env; uses whichever exist.
    for candidate in (ROOT / ".env", ROOT / "app" / ".env"):
        if candidate.exists():
            load_dotenv(candidate)
            print(f"Loaded {candidate.relative_to(ROOT)}")
except ImportError:
    print("(python-dotenv not installed; using the current environment only)")

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

REQUIRED = ["MONGODB_URI", "MONGODB_DATABASE", "INTEGRITY_HMAC_KEY", "ACTOR_SECRET_APPLICATION_SERVICE"]
CHAINED = ["message_records", "spam_patterns", "pattern_events", "audit_logs"]


def is_permission_error(exc: Exception) -> bool:
    """True if Atlas refused the action for permission reasons.
    Atlas reports this as code 13 (Unauthorized) or code 8000 (AtlasError, 'not allowed to do action')."""
    text = str(exc).lower()
    return (
        getattr(exc, "code", None) in (13, 8000)
        or "not allowed to do action" in text
        or "not authorized" in text
        or "unauthorized" in text
    )


def fail(message: str) -> None:
    print(f"\nFAILED: {message}")
    sys.exit(1)


def main() -> None:
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        fail(f"these environment variables are not set: {', '.join(missing)}")

    database = os.environ["MONGODB_DATABASE"]
    if "test" not in database.lower():
        fail(f"MONGODB_DATABASE is '{database}'. Use a database with 'test' in its name for this script.")
    print(f"Database: {database}")

    from app.database.mongodb import (
        ensure_indexes,
        get_client,
        get_db,
        get_message_records_collection,
    )
    from app.database.repository import secure_database_operation
    from app.security.integrity import verify_chain

    if get_client() is None:
        fail("could not connect to Atlas. Check MONGODB_URI, and that your IP is allowed under Atlas > Network Access.")
    print("Connected to Atlas.")

    # 1. Indexes
    ensure_indexes()
    db = get_db()
    for name in CHAINED:
        has_index = "uniq_chain_seq" in db[name].index_information()
        print(f"  index uniq_chain_seq on {name}: {'ok' if has_index else 'MISSING'}")
        if not has_index:
            fail("indexes were not created. The Atlas user needs permission to create indexes.")

    # 2. Create records through the security layer
    credential = os.environ["ACTOR_SECRET_APPLICATION_SERVICE"]
    for i in range(3):
        record = secure_database_operation(
            "APPLICATION_SERVICE",
            "CREATE_MESSAGE",
            "message_records",
            {"message_text": f"TEST {i}: You won 50000 rupees, click to claim", "classification": "SPAM", "risk_score": 92},
            credential=credential,
        )
        print(f"  created message chain_seq={record['chain_seq']}")

    # 3. Verify
    def chain_of(collection):
        return list(collection.find({"chain_seq": {"$exists": True}}).sort("chain_seq", 1))

    messages = get_message_records_collection()
    for name in CHAINED:
        print(f"{name} chain valid: {verify_chain(chain_of(db[name]))}")

    # 4. Optional tamper demo
    if "--tamper" in sys.argv:
        target = messages.find_one({"chain_seq": 2})
        if not target:
            fail("need at least 2 records for the tamper demo")
        original = target["classification"]
        fake = "SAFE" if original != "SAFE" else "SPAM"
        try:
            messages.update_one({"chain_seq": 2}, {"$set": {"classification": fake}})
        except Exception as exc:
            if not is_permission_error(exc):
                fail(f"unexpected error during the update test: {exc}")
            print("\nUpdate was refused by Atlas (not authorized). That is what the restricted app user should do.")
            try:
                # Matches nothing; permissions are checked before anything runs.
                messages.delete_one({"chain_seq": -1})
                print("WARNING: delete was NOT refused. The role is too permissive.")
            except Exception as exc2:
                if is_permission_error(exc2):
                    print("Delete was refused by Atlas (not authorized). Good.")
                else:
                    fail(f"unexpected error during the delete test: {exc2}")
            return
        print(f"\nTampered: record 2 classification {original} -> {fake}")
        print(f"message_records chain valid: {verify_chain(chain_of(messages))}   <- should be False")
        messages.update_one({"chain_seq": 2}, {"$set": {"classification": original}})
        print("Restored the original value.")
        print(f"message_records chain valid: {verify_chain(chain_of(messages))}   <- should be True again")


if __name__ == "__main__":
    main()