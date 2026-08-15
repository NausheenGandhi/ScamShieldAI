"""
agents/contact/impersonation.py

Impersonation risk detection: does the message claim to represent an
organization while the sender doesn't look like that organization's
real channel?

This is a RISK SIGNAL, not a verdict - mentioning "Amazon" in a message
is not proof of impersonation. Detection requires:
    1. The message names a known, commonly-impersonated entity.
    2. The sender doesn't plausibly belong to that entity (e.g. a
       personal mobile number "sending" a bank's account alert).
"""

import re
from typing import Any, Dict, List


# Configurable registry of commonly-impersonated entities. `aliases` are
# matched as whole words/phrases (case-insensitive). `sender_hints` are
# substrings we'd expect in that entity's *real* sender ID, used to avoid
# flagging the entity's own legitimate messages.
IMPERSONATED_ENTITIES: List[Dict[str, Any]] = [
    # Banks
    {"name": "SBI", "aliases": ["sbi", "state bank of india"], "category": "bank", "sender_hints": ["sbi"]},
    {"name": "HDFC Bank", "aliases": ["hdfc", "hdfc bank"], "category": "bank", "sender_hints": ["hdfc", "hdfcbk"]},
    {"name": "ICICI Bank", "aliases": ["icici"], "category": "bank", "sender_hints": ["icici"]},
    {"name": "Axis Bank", "aliases": ["axis bank"], "category": "bank", "sender_hints": ["axis"]},
    {"name": "Kotak Mahindra Bank", "aliases": ["kotak"], "category": "bank", "sender_hints": ["kotak"]},
    {"name": "Punjab National Bank", "aliases": ["pnb", "punjab national bank"], "category": "bank", "sender_hints": ["pnb"]},

    # Payment companies
    {"name": "Paytm", "aliases": ["paytm"], "category": "payment", "sender_hints": ["paytm"]},
    {"name": "PhonePe", "aliases": ["phonepe"], "category": "payment", "sender_hints": ["phonepe"]},
    {"name": "Google Pay", "aliases": ["google pay", "gpay"], "category": "payment", "sender_hints": ["gpay", "google"]},
    {"name": "PayPal", "aliases": ["paypal"], "category": "payment", "sender_hints": ["paypal"]},

    # Delivery / e-commerce
    {"name": "FedEx", "aliases": ["fedex"], "category": "delivery", "sender_hints": ["fedex"]},
    {"name": "Amazon", "aliases": ["amazon"], "category": "ecommerce", "sender_hints": ["amazon", "amzn"]},
    {"name": "Flipkart", "aliases": ["flipkart"], "category": "ecommerce", "sender_hints": ["flipkart", "fkrt"]},
    {"name": "USPS", "aliases": ["usps"], "category": "delivery", "sender_hints": ["usps"]},
    {"name": "DHL", "aliases": ["dhl"], "category": "delivery", "sender_hints": ["dhl"]},
    {"name": "Blue Dart", "aliases": ["blue dart", "bluedart"], "category": "delivery", "sender_hints": ["bluedart"]},
    {"name": "India Post", "aliases": ["india post", "speed post"], "category": "delivery", "sender_hints": ["indpost", "post"]},

    # Government / tax authorities
    {"name": "Income Tax Department", "aliases": ["income tax", "income tax department"], "category": "government", "sender_hints": ["itdept", "incometax"]},
    {"name": "GST", "aliases": ["gst department", "gstn"], "category": "government", "sender_hints": ["gst"]},
    {"name": "Aadhaar / UIDAI", "aliases": ["uidai", "aadhaar"], "category": "government", "sender_hints": ["uidai"]},
    {"name": "RBI", "aliases": ["rbi", "reserve bank of india"], "category": "government", "sender_hints": ["rbi"]},

    # Other frequently spoofed brands
    {"name": "Netflix", "aliases": ["netflix"], "category": "subscription", "sender_hints": ["netflix"]},
    {"name": "Microsoft", "aliases": ["microsoft"], "category": "technology", "sender_hints": ["microsoft", "msft"]},
]


def _find_claimed_entities(message: str) -> List[Dict[str, Any]]:
    text = (message or "").lower()
    matches = []

    for entity in IMPERSONATED_ENTITIES:
        for alias in entity["aliases"]:
            if re.search(rf"\b{re.escape(alias)}\b", text):
                matches.append(entity)
                break

    return matches


def _sender_plausibly_belongs_to(entity: Dict[str, Any], sender_classification: Dict[str, Any]) -> bool:
    normalized = str(sender_classification.get("normalized") or "").lower()
    sender_type = sender_classification.get("sender_type")

    if sender_type not in ("ALPHANUMERIC_SENDER_ID", "SHORT_CODE", "BUSINESS_NUMBER"):
        return False

    return any(hint in normalized for hint in entity.get("sender_hints", []))


def detect_impersonation(
    message: str,
    sender_classification: Dict[str, Any],
    risk_signals: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Returns:
        {
            "detected": bool,
            "claimed_entity": str | None,
            "risk": "LOW" | "MEDIUM" | "HIGH",
            "reason": str,
        }
    """

    claimed = _find_claimed_entities(message)

    if not claimed:
        return {
            "detected": False,
            "claimed_entity": None,
            "risk": "LOW",
            "reason": "Message does not claim to represent a known organization.",
        }

    # If multiple entities are named, evaluate the first (most prominent).
    entity = claimed[0]

    if _sender_plausibly_belongs_to(entity, sender_classification):
        return {
            "detected": False,
            "claimed_entity": entity["name"],
            "risk": "LOW",
            "reason": (
                f"Message references {entity['name']}, and the sender ID "
                "is consistent with that organization's typical sender pattern."
            ),
        }

    # Sender doesn't match - severity depends on what else is going on.
    aggravating = sum([
        bool(risk_signals.get("threat")),
        bool(risk_signals.get("urgency")),
        bool(risk_signals.get("credential_request")),
        bool(risk_signals.get("financial_request")),
        bool(risk_signals.get("suspicious_link")),
    ])

    risk = "HIGH" if aggravating >= 2 else "MEDIUM"

    return {
        "detected": True,
        "claimed_entity": entity["name"],
        "risk": risk,
        "reason": (
            f"Message claims to represent {entity['name']} but originates "
            f"from a sender ({sender_classification.get('sender_type', 'UNKNOWN')}) "
            "that doesn't match that organization's known sender pattern."
        ),
    }