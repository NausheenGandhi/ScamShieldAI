"""
Tests for the ScamShield security layer. No MongoDB connection is needed: the
repository runs against an in-memory FakeCollection.

Run from the project root (the folder that contains app/ and tests/):

    python -m unittest discover -s tests -v
    # or:  pytest tests -v
"""
import copy
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ["INTEGRITY_HMAC_KEY"] = "test-hmac-key"
os.environ["ACTOR_SECRET_APPLICATION_SERVICE"] = "app-secret"
os.environ["ACTOR_SECRET_ADMINISTRATOR"] = "admin-secret"

from pymongo.errors import DuplicateKeyError  # noqa: E402

from app.database import repository as repo  # noqa: E402
from app.security import access_control as ac  # noqa: E402
from app.security.integrity import (  # noqa: E402
    GENESIS_HASH,
    calculate_hash,
    verify_chain,
)

APP = dict(actor="APPLICATION_SERVICE", credential="app-secret")


class FakeCollection:
    """Just enough of a pymongo collection for the repository code, including the
    unique chain_seq index that prevents forks."""

    def __init__(self):
        self.docs = []
        self._next_id = 0

    @staticmethod
    def _match(doc, flt):
        for key, cond in flt.items():
            if isinstance(cond, dict) and "$exists" in cond:
                if (key in doc) != cond["$exists"]:
                    return False
            elif doc.get(key) != cond:
                return False
        return True

    def find_one(self, flt=None, projection=None, sort=None):
        matches = [d for d in self.docs if self._match(d, flt or {})]
        for field, direction in reversed(sort or []):
            matches.sort(key=lambda d: d.get(field, 0), reverse=direction == -1)
        return dict(matches[0]) if matches else None

    def find(self, flt=None):
        return [dict(d) for d in self.docs if self._match(d, flt or {})]

    def count_documents(self, flt, limit=0):
        n = sum(1 for d in self.docs if self._match(d, flt))
        return min(n, limit) if limit else n

    def insert_one(self, doc):
        seq = doc.get("chain_seq")
        if seq is not None and any(d.get("chain_seq") == seq for d in self.docs):
            raise DuplicateKeyError("dup key", 11000, {"keyPattern": {"chain_seq": 1}})
        self._next_id += 1
        doc["_id"] = self._next_id  # pymongo also adds _id to the caller's dict
        self.docs.append(dict(doc))
        return types.SimpleNamespace(inserted_id=self._next_id)

    def chain(self):
        return sorted((d for d in self.docs if "chain_seq" in d), key=lambda d: d["chain_seq"])


class RepoTestCase(unittest.TestCase):
    def setUp(self):
        self.messages = FakeCollection()
        self.patterns = FakeCollection()
        self.events = FakeCollection()
        self.audit = FakeCollection()
        for name, target in [
            ("get_message_records_collection", self.messages),
            ("get_spam_patterns_collection", self.patterns),
            ("get_pattern_events_collection", self.events),
            ("get_audit_logs_collection", self.audit),
        ]:
            patcher = mock.patch.object(repo, name, lambda t=target: t)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(repo, "SPAM_CONFIRM_THRESHOLD", 5)
        patcher.start()
        self.addCleanup(patcher.stop)

    def op(self, operation, resource, data, **auth):
        auth = auth or APP
        return repo.secure_database_operation(
            auth["actor"], operation, resource, data, auth["credential"]
        )

    def new_message(self, text="You won 50000! Click here", **extra):
        return self.op(
            "CREATE_MESSAGE",
            "message_records",
            {"message_text": text, "classification": "SPAM", "risk_score": 92, **extra},
        )

    def audit_events(self, event_type):
        return [d for d in self.audit.docs if d.get("event_type") == event_type]


# ---------------------------------------------------------------------------
# Hash chain
# ---------------------------------------------------------------------------
class HashChainTests(RepoTestCase):
    def test_stored_records_verify_even_though_mongo_added__id(self):
        for i in range(3):
            self.new_message(f"message {i}")
        stored = self.messages.chain()
        self.assertTrue(all("_id" in d for d in stored))
        self.assertTrue(verify_chain(stored))
        self.assertEqual([d["chain_seq"] for d in stored], [1, 2, 3])
        self.assertEqual(stored[0]["previous_hash"], GENESIS_HASH)
        self.assertEqual(stored[1]["previous_hash"], stored[0]["integrity_hash"])

    def test_editing_a_record_is_detected(self):
        for i in range(3):
            self.new_message(f"message {i}")
        self.messages.docs[1]["classification"] = "SAFE"
        self.assertFalse(verify_chain(self.messages.chain()))

    def test_attacker_without_the_key_cannot_repair_the_chain(self):
        for i in range(3):
            self.new_message(f"message {i}")
        self.messages.docs[0]["classification"] = "SAFE"
        with mock.patch.dict(os.environ, {"INTEGRITY_HMAC_KEY": "attacker-guess"}):
            previous = GENESIS_HASH
            for record in self.messages.chain():
                record["previous_hash"] = previous
                record["integrity_hash"] = calculate_hash(record, previous)
                previous = record["integrity_hash"]
        self.assertFalse(verify_chain(self.messages.chain()))

    def test_deleting_a_middle_record_is_detected(self):
        for i in range(3):
            self.new_message(f"message {i}")
        del self.messages.docs[1]
        self.assertFalse(verify_chain(self.messages.chain()))

    def test_hmac_key_is_required(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("INTEGRITY_HMAC_KEY")
            with self.assertRaises(RuntimeError):
                calculate_hash({"a": 1}, GENESIS_HASH)

    def test_chain_head_error_does_not_reset_to_genesis(self):
        self.new_message("first")
        with mock.patch.object(self.messages, "find_one", side_effect=RuntimeError("db down")):
            with self.assertRaises(repo.RepositorySecurityError):
                self.new_message("second")
        self.assertEqual(len(self.messages.docs), 1)

    def test_losing_a_write_race_retries_and_does_not_fork(self):
        self.new_message("first")
        real_head = repo._chain_head
        state = {"stale_used": False}

        def stale_once(collection):
            if collection is self.messages and not state["stale_used"]:
                state["stale_used"] = True
                return 0, GENESIS_HASH  # another writer already took chain_seq 1
            return real_head(collection)

        with mock.patch.object(repo, "_chain_head", side_effect=stale_once):
            self.new_message("second")
        stored = self.messages.chain()
        self.assertEqual([d["chain_seq"] for d in stored], [1, 2])
        self.assertTrue(verify_chain(stored))

    def test_gives_up_cleanly_under_permanent_contention(self):
        self.new_message("first")
        with mock.patch.object(repo, "_chain_head", return_value=(0, GENESIS_HASH)):
            with self.assertRaises(repo.RepositorySecurityError):
                self.new_message("second")
        self.assertEqual(len(self.messages.docs), 1)


# ---------------------------------------------------------------------------
# Patterns: append-only
# ---------------------------------------------------------------------------
class PatternTests(RepoTestCase):
    def new_pattern(self):
        return self.op(
            "CREATE_PATTERN",
            "spam_patterns",
            {"representative_message": "Win a prize now", "embedding": [0.1, 0.2]},
        )

    def bump(self, pattern_id, message_id):
        return self.op(
            "INCREMENT_PATTERN",
            "spam_patterns",
            {"pattern_id": pattern_id, "message_id": message_id},
        )

    def test_pattern_is_confirmed_at_threshold_without_editing_any_record(self):
        pattern = self.new_pattern()
        self.assertNotIn("message_count", pattern)
        self.assertNotIn("status", pattern)
        pid = pattern["pattern_id"]
        snapshot = copy.deepcopy(self.patterns.docs)

        results = [self.bump(pid, f"m{i}") for i in range(1, 5)]
        self.assertEqual([r["message_count"] for r in results], [2, 3, 4, 5])
        self.assertEqual([r["status"] for r in results], ["PENDING"] * 3 + ["CONFIRMED_SPAM"])

        self.assertEqual(self.patterns.docs, snapshot)  # nothing updated in place
        self.assertTrue(verify_chain(self.patterns.chain()))
        self.assertTrue(verify_chain(self.events.chain()))

    def test_same_message_does_not_count_twice(self):
        pid = self.new_pattern()["pattern_id"]
        self.bump(pid, "m1")
        again = self.bump(pid, "m1")
        self.assertEqual(again["message_count"], 2)
        self.assertEqual(len(self.events.docs), 1)

    def test_lookup_by_representative_hash(self):
        pattern = self.new_pattern()
        result = self.op(
            "INCREMENT_PATTERN",
            "spam_patterns",
            {"representative_hash": pattern["representative_hash"], "message_id": "m1"},
        )
        self.assertEqual(result["pattern_id"], pattern["pattern_id"])
        self.assertEqual(result["message_count"], 2)

    def test_confirm_spam_appends_an_event(self):
        pid = self.new_pattern()["pattern_id"]
        result = self.op("CONFIRM_SPAM", "spam_patterns", {"pattern_id": pid})
        self.assertEqual(result["status"], "CONFIRMED_SPAM")
        self.assertEqual(result["message_count"], 1)
        self.assertEqual(self.events.docs[0]["record_type"], "PATTERN_CONFIRMED")

    def test_unknown_pattern_is_rejected(self):
        with self.assertRaises(repo.RepositorySecurityError):
            self.bump("does-not-exist", "m1")

    def test_client_cannot_choose_the_threshold(self):
        pid = self.new_pattern()["pattern_id"]
        with self.assertRaises(ac.SecurityViolation):
            self.op("INCREMENT_PATTERN", "spam_patterns", {"pattern_id": pid, "threshold": 1})


# ---------------------------------------------------------------------------
# Authentication, authorization, audit
# ---------------------------------------------------------------------------
class GatewayTests(RepoTestCase):
    def test_wrong_credential_is_blocked_and_audited(self):
        with self.assertRaises(ac.AuthorizationError):
            self.op("CREATE_MESSAGE", "message_records", {"message_text": "x"},
                    actor="APPLICATION_SERVICE", credential="wrong")
        self.assertEqual(self.messages.docs, [])
        denied = self.audit_events("ACCESS_DENIED")
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["actor"], "UNVERIFIED")
        self.assertEqual(denied[0]["metadata"]["claimed_actor"], "APPLICATION_SERVICE")

    def test_actor_without_configured_secret_cannot_authenticate(self):
        with self.assertRaises(ac.AuthorizationError):
            self.op("CREATE_MESSAGE", "message_records", {"message_text": "x"},
                    actor="AUDIT_SECURITY_SERVICE", credential="anything")

    def test_delete_and_update_are_blocked_even_for_administrator(self):
        for operation in ("DELETE_HISTORY", "UPDATE_HISTORY", "CHANGE_OLD_VERDICT"):
            with self.assertRaises(ac.AuthorizationError):
                self.op(operation, "message_records", {}, actor="ADMINISTRATOR", credential="admin-secret")
        self.assertEqual(len(self.audit_events("ACCESS_DENIED")), 3)

    def test_operation_must_match_resource(self):
        with self.assertRaises(ac.AuthorizationError):
            self.op("CREATE_MESSAGE", "spam_patterns", {"message_text": "x"})

    def test_client_cannot_supply_hashes_ids_or_timestamps(self):
        for field in ("integrity_hash", "previous_hash", "chain_seq", "timestamp", "message_hash", "status"):
            with self.assertRaises(ac.SecurityViolation, msg=field):
                self.op("CREATE_MESSAGE", "message_records", {"message_text": "x", field: "forged"})
        for field in ("message_id", "unexpected"):
            with self.assertRaises(ac.SecurityViolation, msg=field):
                self.op("CREATE_MESSAGE", "message_records", {"message_text": "x", field: "y"})
        self.assertEqual(self.messages.docs, [])

    def test_ids_are_server_generated_and_unique(self):
        a = self.new_message("same text")
        b = self.new_message("same text")
        self.assertNotEqual(a["message_id"], b["message_id"])
        self.assertEqual(a["message_hash"], b["message_hash"])

    def test_processing_path_is_limited_to_known_values(self):
        self.assertEqual(self.new_message()["processing_path"], "LANGGRAPH")
        fast = self.new_message(processing_path="SEMANTIC_FAST_PATH")
        self.assertEqual(fast["processing_path"], "SEMANTIC_FAST_PATH")
        with self.assertRaises(ac.SecurityViolation):
            self.new_message(processing_path="ANYTHING")

    def test_successful_operation_is_audited_with_authenticated_actor(self):
        record = self.new_message()
        executed = self.audit_events("OPERATION_EXECUTED")
        self.assertEqual(len(executed), 1)
        self.assertEqual(executed[0]["actor"], "APPLICATION_SERVICE")
        self.assertEqual(executed[0]["resource_id"], record["message_id"])
        self.assertTrue(verify_chain(self.audit.chain()))

    def test_audit_actor_cannot_be_forged(self):
        with self.assertRaises(ac.SecurityViolation):
            self.op("CREATE_AUDIT_EVENT", "audit_logs", {"event_type": "LOGIN", "actor": "ADMINISTRATOR"})
        record = self.op("CREATE_AUDIT_EVENT", "audit_logs", {"event_type": "LOGIN"},
                         actor="application_service", credential="app-secret")
        self.assertEqual(record["actor"], "APPLICATION_SERVICE")

    def test_client_cannot_write_server_only_event_types(self):
        with self.assertRaises(ac.SecurityViolation):
            self.op("CREATE_AUDIT_EVENT", "audit_logs", {"event_type": "ACCESS_DENIED"})


# ---------------------------------------------------------------------------
# Input validation (no DB involved)
# ---------------------------------------------------------------------------
class ValidationTests(unittest.TestCase):
    def check(self, data, operation="CREATE_MESSAGE", resource="message_records"):
        return ac.validate_request_data(operation, resource, data)

    def test_valid_message_is_normalized(self):
        safe = self.check({"message_text": "hi", "classification": "spam", "risk_score": 10})
        self.assertEqual(safe["classification"], "SPAM")

    def test_rejects_bad_values(self):
        bad = [
            {"message_text": "x" * (ac.MAX_TEXT_CHARS + 1)},
            {"message_text": 123},
            {"message_text": "x", "classification": "MAYBE"},
            {"message_text": "x", "risk_score": 101},
            {"message_text": "x", "risk_score": -1},
            {"message_text": "x", "risk_score": True},
            {"message_text": "x", "risk_score": float("nan")},
            {"message_text": "x", "metadata": "not a dict"},
            {"message_text": "x", "metadata": {"blob": "y" * (ac.MAX_METADATA_BYTES + 1)}},
            {},
        ]
        for data in bad:
            with self.assertRaises(ac.SecurityViolation, msg=str(data)[:60]):
                self.check(data)

    def test_embedding_checks(self):
        ok = {"representative_message": "m", "embedding": [0.1, 0.2]}
        self.check(ok, "CREATE_PATTERN", "spam_patterns")
        for embedding in ([0.1, "x"], [float("inf")], list(range(ac.MAX_EMBEDDING_DIM + 1)), "abc"):
            with self.assertRaises(ac.SecurityViolation):
                self.check({"representative_message": "m", "embedding": embedding},
                           "CREATE_PATTERN", "spam_patterns")

    def test_non_dict_payload_is_rejected(self):
        with self.assertRaises(ac.SecurityViolation):
            self.check(["message_text"])


if __name__ == "__main__":
    unittest.main()