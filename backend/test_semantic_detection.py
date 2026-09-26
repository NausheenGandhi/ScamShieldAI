import os
import unittest
from unittest.mock import patch

from app.database.mongodb import close_mongo_client, get_client
from app.services.embedding_service import generate_embedding
from app.services.semantic_spam_service import semantic_precheck


class SemanticDetectionTests(unittest.TestCase):
    def tearDown(self):
        close_mongo_client()

    def test_generate_embedding_returns_vector(self):
        embedding = generate_embedding("Congratulations! You won ₹50,000")
        self.assertIsInstance(embedding, list)
        self.assertGreater(len(embedding), 0)
        self.assertTrue(all(isinstance(value, float) for value in embedding))

    def test_semantic_precheck_returns_decision_without_db(self):
        with patch.dict("os.environ", {}, clear=False):
            os.environ.pop("MONGODB_URI", None)
            os.environ.pop("MONGODB_DATABASE", None)
            close_mongo_client()

            result = semantic_precheck("Congratulations! You won ₹50,000", "sender-1")
            self.assertIsNone(get_client())
            self.assertIn("should_continue", result)
            self.assertIn("processing_path", result)


if __name__ == "__main__":
    unittest.main()
