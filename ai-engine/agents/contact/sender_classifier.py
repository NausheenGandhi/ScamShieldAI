"""
agents/contact/sender_classifier.py

Classifies an SMS sender identifier into a sender-ID type:

    PERSONAL_NUMBER        - looks like an individual's mobile number
    BUSINESS_NUMBER        - landline / toll-free / VOIP / UAN style number
    ALPHANUMERIC_SENDER_ID - e.g. "HDFCBK", "AD-SBIINB", "VM-AMAZON"
    SHORT_CODE              - short numeric code, e.g. "56070", "121"
    SUSPICIOUS               - looks like a phone number but is malformed /
                                spoofed-looking
    UNKNOWN                  - not enough signal to say anything useful

This is a SIGNAL, not a verdict. A PERSONAL_NUMBER is not automatically
risky, and an ALPHANUMERIC_SENDER_ID is not automatically trustworthy -
downstream (trust_score.py) is responsible for combining this with other
evidence.
"""

import re
from typing import Any, Dict

import phonenumbers
from phonenumbers import PhoneNumberType, NumberParseException


DEFAULT_REGION = "IN"  # India, per this project's target market

SHORT_CODE_MIN_LEN = 3
SHORT_CODE_MAX_LEN = 6

# Number types phonenumbers can return that generally indicate an
# organization/business line rather than a personal mobile.
_BUSINESS_NUMBER_TYPES = {
    PhoneNumberType.FIXED_LINE,
    PhoneNumberType.TOLL_FREE,
    PhoneNumberType.PREMIUM_RATE,
    PhoneNumberType.SHARED_COST,
    PhoneNumberType.VOIP,
    PhoneNumberType.UAN,
    PhoneNumberType.PAGER,
}

_PERSONAL_NUMBER_TYPES = {
    PhoneNumberType.MOBILE,
    PhoneNumberType.FIXED_LINE_OR_MOBILE,
}


def _clean(sender: str) -> str:
    return (sender or "").strip()


def _digits_only(sender: str) -> str:
    return re.sub(r"[^\d]", "", sender or "")


def classify_sender(sender: str, default_region: str = DEFAULT_REGION) -> Dict[str, Any]:
    """
    Returns:
        {
            "sender_type": "...",
            "confidence": 0.0-1.0,
            "reason": "...",
            "normalized": "<E.164 number, or cleaned sender ID, or None>",
        }
    """

    raw = _clean(sender)

    if not raw or raw.lower() == "unknown":
        return {
            "sender_type": "UNKNOWN",
            "confidence": 0.2,
            "reason": "No usable sender information was provided.",
            "normalized": None,
        }

    digits = _digits_only(raw)
    has_letters = bool(re.search(r"[A-Za-z]", raw))

    # --------------------------------------------------------------
    # 1. Pure digits -> either a short code or a real phone number
    # --------------------------------------------------------------
    if digits and not has_letters:

        # Short codes are typically 3-6 digits with no country code and
        # are used by banks, telcos, and OTP/notification services.
        if SHORT_CODE_MIN_LEN <= len(digits) <= SHORT_CODE_MAX_LEN:
            return {
                "sender_type": "SHORT_CODE",
                "confidence": 0.85,
                "reason": (
                    f"Sender is a {len(digits)}-digit numeric code, "
                    "typical of short-code SMS senders used by banks, "
                    "telcos, or OTP/notification services."
                ),
                "normalized": digits,
            }

        return _classify_phone_number(raw, digits, default_region)

    # --------------------------------------------------------------
    # 2. Contains letters -> alphanumeric sender ID, or junk
    # --------------------------------------------------------------
    if has_letters:
        return _classify_alphanumeric(raw)

    return {
        "sender_type": "UNKNOWN",
        "confidence": 0.3,
        "reason": "Sender format did not match any known pattern.",
        "normalized": raw,
    }


def _classify_phone_number(raw: str, digits: str, default_region: str) -> Dict[str, Any]:

    candidate = raw if raw.startswith("+") else digits

    try:
        parsed = phonenumbers.parse(candidate, default_region)
    except NumberParseException:
        parsed = None

    if parsed is not None and phonenumbers.is_valid_number(parsed):

        number_type = phonenumbers.number_type(parsed)
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)

        if number_type in _PERSONAL_NUMBER_TYPES:
            return {
                "sender_type": "PERSONAL_NUMBER",
                "confidence": 0.95,
                "reason": "Sender is a valid mobile phone number.",
                "normalized": e164,
            }

        if number_type in _BUSINESS_NUMBER_TYPES:
            return {
                "sender_type": "BUSINESS_NUMBER",
                "confidence": 0.85,
                "reason": (
                    "Sender is a valid phone number of a type "
                    "(landline/toll-free/VOIP/UAN) commonly used by "
                    "organizations rather than individuals."
                ),
                "normalized": e164,
            }

        return {
            "sender_type": "UNKNOWN",
            "confidence": 0.5,
            "reason": "Sender is a valid phone number of an indeterminate type.",
            "normalized": e164,
        }

    # Looks phone-number-ish (7-15 digits) but failed validation - this
    # is a signal worth flagging (malformed / spoofed sender), not proof
    # of anything.
    if 7 <= len(digits) <= 15:
        return {
            "sender_type": "SUSPICIOUS",
            "confidence": 0.5,
            "reason": (
                "Sender resembles a phone number but is not a valid, "
                "dialable number for the expected region."
            ),
            "normalized": digits,
        }

    return {
        "sender_type": "UNKNOWN",
        "confidence": 0.3,
        "reason": "Sender is numeric but does not match a recognizable phone or short-code pattern.",
        "normalized": digits,
    }


def _classify_alphanumeric(raw: str) -> Dict[str, Any]:

    # Strip common DLT-style telecom prefixes, e.g. "VM-AMAZON", "AD-SBIINB"
    cleaned = re.sub(r"^[A-Za-z]{2}-", "", raw).strip()

    # Typical Indian alphanumeric sender IDs are 6 characters, but we
    # allow a bit of slack since formats vary by carrier/country.
    if 2 <= len(cleaned) <= 11 and re.fullmatch(r"[A-Za-z0-9]+", cleaned):
        return {
            "sender_type": "ALPHANUMERIC_SENDER_ID",
            "confidence": 0.8,
            "reason": (
                "Sender is a short alphanumeric ID, typical of registered "
                "business/brand SMS senders."
            ),
            "normalized": cleaned.upper(),
        }

    # Long, odd-shaped alphanumeric strings mixing letters/digits/symbols
    # don't match any normal sender ID pattern - flag rather than trust.
    if len(raw) > 11:
        return {
            "sender_type": "SUSPICIOUS",
            "confidence": 0.45,
            "reason": (
                "Sender ID is unusually long/irregular for a standard "
                "alphanumeric sender ID."
            ),
            "normalized": raw,
        }

    return {
        "sender_type": "UNKNOWN",
        "confidence": 0.3,
        "reason": "Sender format could not be confidently classified.",
        "normalized": raw,
    }