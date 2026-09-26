from __future__ import annotations

import hmac
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

from .hashing import hmac_sha256_hex

GENESIS_HASH = "GENESIS"

# Fields that are never part of the hashed payload. "_id" is assigned by MongoDB
# after insert, so it must be excluded or every stored record would fail verification.
_NON_HASHED_FIELDS = {"_id", "previous_hash", "integrity_hash"}


def _hashable(record: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in record.items() if k not in _NON_HASHED_FIELDS}


def _same(a: Any, b: Any) -> bool:
    return isinstance(a, str) and isinstance(b, str) and hmac.compare_digest(a, b)


def calculate_hash(record: Dict[str, Any], previous_hash: Optional[str] = None) -> str:
    payload = {
        "previous_hash": previous_hash or GENESIS_HASH,
        "record": _hashable(record),
    }
    return hmac_sha256_hex(payload)


def verify_record(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    previous_hash = record.get("previous_hash")
    integrity_hash = record.get("integrity_hash")
    if not previous_hash or not integrity_hash:
        return False
    return _same(calculate_hash(record, previous_hash), integrity_hash)


def verify_chain(records: Iterable[Dict[str, Any]]) -> bool:
    """Verify a whole chain. `records` must be sorted by chain_seq ascending."""
    previous = GENESIS_HASH
    expected_seq = 1
    for record in records:
        if not isinstance(record, dict):
            return False
        if record.get("previous_hash") != previous:
            return False
        if record.get("chain_seq") != expected_seq:
            return False
        if not _same(calculate_hash(record, previous), record.get("integrity_hash")):
            return False
        previous = record["integrity_hash"]
        expected_seq += 1
    return True


def validate_hash_chain(records: Iterable[Dict[str, Any]]) -> bool:
    return verify_chain(records)


def verify_integrity(record: Dict[str, Any], previous_hash: Optional[str] = None) -> bool:
    if not isinstance(record, dict):
        return False
    effective_previous = previous_hash or record.get("previous_hash") or GENESIS_HASH
    return _same(calculate_hash(record, effective_previous), record.get("integrity_hash"))


def append_hash_chain(record_type: str, payload: Dict[str, Any], previous_hash: Optional[str] = None) -> Dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()
    base_record = {
        "record_type": record_type,
        "timestamp": timestamp,
        **payload,
    }
    effective_previous = previous_hash or GENESIS_HASH
    integrity_hash = calculate_hash(base_record, effective_previous)
    base_record["previous_hash"] = effective_previous
    base_record["integrity_hash"] = integrity_hash
    return base_record