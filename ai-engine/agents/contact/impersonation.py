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

SHORT CODE HANDLING - WHY IT'S SPLIT BY "domestic":
Under TRAI's DLT regulation, transactional SMS in India (this includes
OTP messages) must be sent from a registered 6-character alphanumeric
header (e.g. "HDFCSE", "SBIINB"), prefixed by a 2-letter operator/circle
code (e.g. "AX-HDFCSE"). This is a hard requirement for banks and
applies broadly to any India-registered Principal Entity sending
transactional/commercial SMS - not just banks.
    Source: TRAI DLT transactional-SMS regulation summaries (2026);
    see e.g. Alibaba Cloud's "Regulatory requirements for sending SMS
    to India" and smsheader.info's HDFC header lookup.

The one documented exception: alphanumeric sender IDs are NOT supported
for messages routed from outside India, so genuinely foreign senders
(a US-based PayPal/Netflix/Microsoft notification system, for example)
can legitimately arrive as a random-looking numeric short code instead.

Practical effect:
    - "domestic" entities (Indian banks, government bodies, Indian
      payment apps, India-registered e-commerce/courier) claimed by a
      message from a bare numeric SHORT_CODE sender: this is NOT how
      they are legally allowed to send transactional SMS, so treat it
      as a genuine mismatch, not just "unverified."
    - "foreign" entities (brands that plausibly route SMS from outside
      India) claimed by a SHORT_CODE sender: this can be legitimate, so
      it is NOT held against them by default.

We deliberately do NOT hardcode specific real short-code numbers here -
they vary by telecom circle/operator, aren't reliably published, and a
wrong guess in a security tool is worse than no guess. If you obtain a
VERIFIED list of an entity's real numeric short codes from an
authoritative source, add them to that entity's `short_codes` list and
they will be matched directly.
"""

import re
from typing import Any, Dict, List


# Configurable registry of commonly-impersonated entities.
#
#   aliases       matched as whole words/phrases in the message text
#                 (case-insensitive).
#   sender_hints  substrings expected in this entity's real ALPHANUMERIC
#                 sender ID or BUSINESS_NUMBER (e.g. "hdfc" in "HDFCBK"
#                 or "HDFCSE"). Substring matching is intentional - it
#                 stays correct even if the exact registered header
#                 changes, as long as it contains the brand abbreviation.
#   short_codes   known, VERIFIED numeric short codes this entity sends
#                 from. Empty by default - see module docstring. Do not
#                 populate with guesses.
#   domestic      True if this entity, when legitimate, is required to
#                 send Indian transactional SMS via a DLT-registered
#                 alphanumeric header (so a numeric short code claiming
#                 to be them is a real red flag). False for entities
#                 that plausibly route SMS from outside India, where a
#                 numeric short code can be legitimate.
IMPERSONATED_ENTITIES: List[Dict[str, Any]] = [
    # Banks - domestic, DLT-regulated, alphanumeric headers required
    {"name": "SBI", "aliases": ["sbi", "state bank of india"], "category": "bank", "sender_hints": ["sbi"], "short_codes": [], "domestic": True},
    {"name": "HDFC Bank", "aliases": ["hdfc", "hdfc bank"], "category": "bank", "sender_hints": ["hdfc"], "short_codes": [], "domestic": True},
    {"name": "ICICI Bank", "aliases": ["icici"], "category": "bank", "sender_hints": ["icici"], "short_codes": [], "domestic": True},
    {"name": "Axis Bank", "aliases": ["axis bank"], "category": "bank", "sender_hints": ["axis"], "short_codes": [], "domestic": True},
    {"name": "Kotak Mahindra Bank", "aliases": ["kotak"], "category": "bank", "sender_hints": ["kotak"], "short_codes": [], "domestic": True},
    {"name": "Punjab National Bank", "aliases": ["pnb", "punjab national bank"], "category": "bank", "sender_hints": ["pnb"], "short_codes": [], "domestic": True},

    # Payment companies - Indian-registered apps, DLT applies
    {"name": "Paytm", "aliases": ["paytm"], "category": "payment", "sender_hints": ["paytm"], "short_codes": [], "domestic": True},
    {"name": "PhonePe", "aliases": ["phonepe"], "category": "payment", "sender_hints": ["phonepe"], "short_codes": [], "domestic": True},
    {"name": "Google Pay", "aliases": ["google pay", "gpay"], "category": "payment", "sender_hints": ["gpay", "google"], "short_codes": [], "domestic": True},
    # PayPal has no India DLT presence for consumer notifications - SMS
    # to Indian numbers is plausibly routed internationally.
    {"name": "PayPal", "aliases": ["paypal"], "category": "payment", "sender_hints": ["paypal"], "short_codes": [], "domestic": False},

    # Delivery / e-commerce
    # FedEx/DHL/USPS: foreign carriers, plausibly route notifications
    # from outside India.
    {"name": "FedEx", "aliases": ["fedex"], "category": "delivery", "sender_hints": ["fedex"], "short_codes": [], "domestic": False},
    {"name": "DHL", "aliases": ["dhl"], "category": "delivery", "sender_hints": ["dhl"], "short_codes": [], "domestic": False},
    {"name": "USPS", "aliases": ["usps"], "category": "delivery", "sender_hints": ["usps"], "short_codes": [], "domestic": False},
    # Amazon/Flipkart/Blue Dart/India Post operate India-registered
    # entities for domestic delivery notifications.
    {"name": "Amazon", "aliases": ["amazon"], "category": "ecommerce", "sender_hints": ["amazon", "amzn"], "short_codes": [], "domestic": True},
    {"name": "Flipkart", "aliases": ["flipkart"], "category": "ecommerce", "sender_hints": ["flipkart", "fkrt"], "short_codes": [], "domestic": True},
    {"name": "Blue Dart", "aliases": ["blue dart", "bluedart"], "category": "delivery", "sender_hints": ["bluedart"], "short_codes": [], "domestic": True},
    {"name": "India Post", "aliases": ["india post", "speed post"], "category": "delivery", "sender_hints": ["indpost", "post"], "short_codes": [], "domestic": True},

    # Government / tax authorities - always domestic
    {"name": "Income Tax Department", "aliases": ["income tax", "income tax department"], "category": "government", "sender_hints": ["itdept", "incometax"], "short_codes": [], "domestic": True},
    {"name": "GST", "aliases": ["gst department", "gstn"], "category": "government", "sender_hints": ["gst"], "short_codes": [], "domestic": True},
    {"name": "Aadhaar / UIDAI", "aliases": ["uidai", "aadhaar"], "category": "government", "sender_hints": ["uidai"], "short_codes": [], "domestic": True},
    {"name": "RBI", "aliases": ["rbi", "reserve bank of india"], "category": "government", "sender_hints": ["rbi"], "short_codes": [], "domestic": True},

    # Other frequently spoofed brands - foreign, plausibly routed
    # internationally
    {"name": "Netflix", "aliases": ["netflix"], "category": "subscription", "sender_hints": ["netflix"], "short_codes": [], "domestic": False},
    {"name": "Microsoft", "aliases": ["microsoft"], "category": "technology", "sender_hints": ["microsoft", "msft"], "short_codes": [], "domestic": False},
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


def _sender_plausibility(entity: Dict[str, Any], sender_classification: Dict[str, Any]) -> str:
    """
    Returns one of:
        "MATCH"      - sender is consistent with this entity's known
                       pattern (alphanumeric hint, or a verified short
                       code on file).
        "MISMATCH"   - sender pattern actively contradicts this entity:
                       a personal number, an alphanumeric ID/business
                       number that doesn't match anything on file, or
                       (for a "domestic" entity) a bare numeric short
                       code, which domestic entities are not permitted
                       to send transactional SMS from.
        "UNVERIFIED" - genuinely can't confirm or deny, e.g. a foreign
                       entity's SMS arriving as an unverified short
                       code, which can be legitimate. Must NOT be
                       treated as evidence of impersonation.
    """
    normalized = str(sender_classification.get("normalized") or "").lower()
    sender_type = sender_classification.get("sender_type")

    if sender_type == "SHORT_CODE":
        known_codes = entity.get("short_codes") or []
        digits = re.sub(r"[^\d]", "", normalized)

        if known_codes:
            return "MATCH" if digits in known_codes else "MISMATCH"

        # No verified codes on file. For a domestic entity this is a
        # real mismatch (they're required to use an alphanumeric DLT
        # header, not a bare short code). For a foreign entity it's
        # genuinely unverifiable, since legitimate international SMS
        # can land as a short code.
        return "MISMATCH" if entity.get("domestic", True) else "UNVERIFIED"

    if sender_type in ("ALPHANUMERIC_SENDER_ID", "BUSINESS_NUMBER"):
        if any(hint in normalized for hint in entity.get("sender_hints", [])):
            return "MATCH"
        return "MISMATCH"

    # PERSONAL_NUMBER, SUSPICIOUS, UNKNOWN, etc. never plausibly belong
    # to an organization's official channel.
    return "MISMATCH"


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
    plausibility = _sender_plausibility(entity, sender_classification)

    if plausibility == "MATCH":
        return {
            "detected": False,
            "claimed_entity": entity["name"],
            "risk": "LOW",
            "reason": (
                f"Message references {entity['name']}, and the sender ID "
                "is consistent with that organization's known sender pattern."
            ),
        }

    if plausibility == "UNVERIFIED":
        return {
            "detected": False,
            "claimed_entity": entity["name"],
            "risk": "LOW",
            "reason": (
                f"Message references {entity['name']} from a short-code "
                "sender. This organization may legitimately send SMS via "
                "an international short code, so the sender's identity "
                "could not be confirmed either way - this is not treated "
                "as a red flag on its own."
            ),
        }

    # MISMATCH - build a reason that's specific to *why* it mismatched.
    sender_type = sender_classification.get("sender_type", "UNKNOWN")

    if sender_type == "SHORT_CODE" and entity.get("domestic", True):
        reason = (
            f"Message claims to represent {entity['name']}, but arrives from a "
            "bare numeric short code. Indian transactional SMS from this type "
            "of organization is required to use a registered alphanumeric "
            "sender ID (e.g. \"HDFCBK\"), not a plain short code - this is "
            "inconsistent with how they actually send messages."
        )
    else:
        reason = (
            f"Message claims to represent {entity['name']} but originates "
            f"from a sender ({sender_type}) that doesn't match that "
            "organization's known sender pattern."
        )

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
        "reason": reason,
    }