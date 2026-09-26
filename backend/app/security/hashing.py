import hashlib
import hmac
import json
import os
from typing import Any


def _canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _canonicalize(value[k]) for k in sorted(value.keys(), key=lambda item: str(item))}
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, tuple):
        return [_canonicalize(item) for item in value]
    if isinstance(value, set):
        return [_canonicalize(item) for item in sorted(value, key=lambda item: json.dumps(_canonicalize(item), sort_keys=True, separators=(",", ":"), ensure_ascii=False))]
    return value


def canonical_json(value: Any) -> str:
    normalized = _canonicalize(value)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(value: Any) -> str:
    """Plain (unkeyed) SHA-256. Use for content fingerprints such as message_hash."""
    payload = canonical_json(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def hash_value(value: Any) -> str:
    return sha256_hex(value)


def _integrity_key() -> bytes:
    key = os.environ.get("INTEGRITY_HMAC_KEY")
    if not key:
        raise RuntimeError(
            "INTEGRITY_HMAC_KEY is not set. Refusing to build or verify the hash chain "
            "without a secret key that lives outside MongoDB."
        )
    return key.encode("utf-8")


def hmac_sha256_hex(value: Any) -> str:
    """Keyed hash (HMAC-SHA256). Use for the integrity chain so that someone who can
    only write to MongoDB cannot recompute valid hashes after editing a record."""
    payload = canonical_json(value).encode("utf-8")
    return hmac.new(_integrity_key(), payload, hashlib.sha256).hexdigest()