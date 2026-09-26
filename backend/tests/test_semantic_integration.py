"""
End-to-end test: semantic_precheck -> secure repository -> fake in-memory collections.

The embedding model is replaced by a tiny stand-in, so this runs fast and needs
neither the real model nor MongoDB.
"""
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ["INTEGRITY_HMAC_KEY"] = "test-hmac-key"
os.environ["ACTOR_SECRET_APPLICATION_SERVICE"] = "app-secret"

# Avoid loading the real embedding model in tests.
if "app.services.embedding_service" not in sys.modules:
    stub = types.ModuleType("app.services.embedding_service")
    stub.generate_embedding = lambda text: [1.0, 0.0]
    sys.modules["app.services.embedding_service"] = stub

from app.database import repository as repo  # noqa: E402
from app.security.integrity import verify_chain  # noqa: E402
from app.services import semantic_spam_service as svc  # noqa: E402
from test_security_layer import FakeCollection  # noqa: E402


def fake_embedding(text):
    """Prize-related texts get one vector, everything else an orthogonal one."""
    return [1.0, 0.0] if "prize" in text.lower() else [0.0, 1.0]


class SemanticFlowTests(unittest.TestCase):
    def setUp(self):
        self.messages = FakeCollection()
        self.patterns = FakeCollection()
        self.events = FakeCollection()
        self.audit = FakeCollection()
        patches = [
            mock.patch.object(repo, "get_message_records_collection", lambda: self.messages),
            mock.patch.object(repo, "get_spam_patterns_collection", lambda: self.patterns),
            mock.patch.object(repo, "get_pattern_events_collection", lambda: self.events),
            mock.patch.object(repo, "get_audit_logs_collection", lambda: self.audit),
            mock.patch.object(svc, "get_spam_patterns_collection", lambda: self.patterns),
            mock.patch.object(svc, "generate_embedding", fake_embedding),
            mock.patch.object(repo, "SPAM_CONFIRM_THRESHOLD", 5),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_pattern_lifecycle_through_the_secure_layer(self):
        texts = [f"You won a prize, claim it now #{i}" for i in range(6)]

        first = svc.semantic_precheck(texts[0], "sender-1")
        self.assertFalse(first["matched"])
        self.assertEqual(len(self.patterns.docs), 1)

        statuses = []
        for text in texts[1:5]:
            result = svc.semantic_precheck(text, "sender-1")
            self.assertTrue(result["matched"])
            statuses.append(result["pattern_status"])
        # count goes 2, 3, 4, 5 -> confirmed on the fifth message overall
        self.assertEqual(statuses, ["PENDING", "PENDING", "PENDING", "CONFIRMED_SPAM"])

        sixth = svc.semantic_precheck(texts[5], "sender-1")
        self.assertTrue(sixth["fast_path_spam"])
        self.assertFalse(sixth["should_continue"])

        # Messages were stored (they used to be silently rejected), with the right path.
        self.assertEqual(len(self.messages.docs), 5)
        self.assertEqual(self.messages.chain()[-1]["processing_path"], "SEMANTIC_FAST_PATH")

        # Nothing was edited in place and every chain verifies.
        self.assertEqual(len(self.patterns.docs), 1)
        for collection in (self.messages, self.patterns, self.events, self.audit):
            self.assertTrue(verify_chain(collection.chain()))

    def test_unrelated_message_starts_a_new_pattern(self):
        svc.semantic_precheck("You won a prize, claim it now", "s")
        result = svc.semantic_precheck("Your parcel is waiting at the depot", "s")
        self.assertFalse(result["matched"])
        self.assertEqual(len(self.patterns.docs), 2)

    def test_missing_secret_blocks_writes_but_does_not_crash(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("ACTOR_SECRET_APPLICATION_SERVICE")
            result = svc.semantic_precheck("You won a prize, claim it now", "s")
        self.assertFalse(result["matched"])
        self.assertEqual(self.patterns.docs, [])


if __name__ == "__main__":
    unittest.main()