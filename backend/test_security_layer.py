import json
import unittest

from app.security.access_control import AuthorizationError, validate_operation_policy
from app.security.hashing import canonical_json, sha256_hex
from app.security.integrity import GENESIS_HASH, calculate_hash, verify_integrity
from app.database.repository import secure_database_operation


class SecurityLayerTests(unittest.TestCase):
    def test_authorization_rejects_unsafe_operation(self):
        with self.assertRaises(AuthorizationError):
            validate_operation_policy("USER", "DELETE_HISTORY", "message_records", {})

    def test_canonical_hash_is_deterministic(self):
        payload = {"b": 2, "a": 1, "nested": {"d": 4, "c": 3}}
        first = canonical_json(payload)
        second = canonical_json(payload)
        self.assertEqual(first, second)
        self.assertEqual(json.loads(first), {"a": 1, "b": 2, "nested": {"c": 3, "d": 4}})

    def test_hash_chain_verifies_record_integrity(self):
        record = {"message": "hello", "risk_score": 99}
        integrity = calculate_hash(record, GENESIS_HASH)
        self.assertTrue(verify_integrity({**record, "integrity_hash": integrity}, GENESIS_HASH))

    def test_secure_repository_rejects_tampering_fields(self):
        with self.assertRaises(Exception):
            secure_database_operation(
                "APPLICATION_SERVICE",
                "CREATE_MESSAGE",
                "message_records",
                {
                    "message_text": "hello",
                    "previous_hash": "forged",
                    "integrity_hash": "forged",
                },
            )


if __name__ == "__main__":
    unittest.main()
