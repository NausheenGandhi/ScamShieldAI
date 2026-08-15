"""
agents/contact/trust_score.py

Combines every signal the Contact Agent gathers into a single 0-100
trust score and verdict.

Weights are centralized here (not scattered across the codebase) so they
can be tuned without touching detection logic elsewhere.
"""

from typing import Any, Dict


WEIGHTS = {
    "saved_contact": 0.20,
    "sender_type": 0.15,
    "sender_reputation": 0.20,
    "message_context": 0.25,
    "impersonation": 0.10,
    "spam_scam_probability": 0.10,
}

assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-6, "trust score weights must sum to 1.0"


SENDER_TYPE_TRUST = {
    # 0-100 baseline trust purely from the sender-ID *type*. This is a
    # weak prior, not a verdict - it only contributes 15% of the total.
    "PERSONAL_NUMBER": 60,
    "BUSINESS_NUMBER": 65,
    "ALPHANUMERIC_SENDER_ID": 70,
    "SHORT_CODE": 65,
    "UNKNOWN": 45,
    "SUSPICIOUS": 15,
}

IMPERSONATION_RISK_TRUST = {
    "LOW": 100,
    "MEDIUM": 45,
    "HIGH": 5,
}


def _saved_contact_component(is_saved_contact: bool, burst_detected: bool, repeated_content: bool) -> float:
    """
    Saved contact ≠ automatically trusted. A saved contact whose account
    looks compromised (burst/repeated blasting) gets no benefit here.
    """

    if not is_saved_contact:
        return 45.0  # neutral-low, NOT automatically suspicious

    if burst_detected or repeated_content:
        return 30.0  # compromised-looking behavior overrides the "saved" benefit

    return 95.0


def _message_context_component(risk_signals: Dict[str, Any]) -> float:
    """
    Starts at 100 (no evidence of harm) and is deducted per triggered
    signal. Every deduction is visible/explainable via risk_signals.
    """

    score = 100.0

    deductions = {
        "credential_request": 30,
        "financial_request": 25,
        "threat": 20,
        "secrecy_request": 20,
        "urgency": 10,
        "suspicious_link": 15,
        "personal_info_request": 15,
        "prize_scam": 15,
        "delivery_payment_scam": 15,
    }

    for signal, penalty in deductions.items():
        if risk_signals.get(signal):
            score -= penalty

    return max(0.0, score)


def _spam_scam_component(spam_probability: float, scam_probability: float) -> float:
    worst = max(spam_probability or 0.0, scam_probability or 0.0)
    return max(0.0, 100.0 * (1.0 - worst))


def calculate_trust_score(
    is_saved_contact: bool,
    burst_detected: bool,
    repeated_content: bool,
    sender_type: str,
    sender_reputation_score: float,
    risk_signals: Dict[str, Any],
    impersonation_risk: str,
    spam_probability: float,
    scam_probability: float,
) -> Dict[str, Any]:

    saved_contact_component = _saved_contact_component(is_saved_contact, burst_detected, repeated_content)
    sender_type_component = SENDER_TYPE_TRUST.get(sender_type, SENDER_TYPE_TRUST["UNKNOWN"])
    reputation_component = max(0.0, min(100.0, sender_reputation_score))
    context_component = _message_context_component(risk_signals)
    impersonation_component = IMPERSONATION_RISK_TRUST.get(impersonation_risk, 50)
    spam_scam_component = _spam_scam_component(spam_probability, scam_probability)

    weighted = (
        saved_contact_component * WEIGHTS["saved_contact"]
        + sender_type_component * WEIGHTS["sender_type"]
        + reputation_component * WEIGHTS["sender_reputation"]
        + context_component * WEIGHTS["message_context"]
        + impersonation_component * WEIGHTS["impersonation"]
        + spam_scam_component * WEIGHTS["spam_scam_probability"]
    )

    score = int(round(max(0.0, min(100.0, weighted))))

    if score >= 80:
        verdict = "TRUSTED"
    elif score >= 60:
        verdict = "LOW_RISK"
    elif score >= 40:
        verdict = "CAUTION"
    elif score >= 20:
        verdict = "SUSPICIOUS"
    else:
        verdict = "HIGH_RISK"

    return {
        "score": score,
        "verdict": verdict,
        "components": {
            "saved_contact": round(saved_contact_component, 1),
            "sender_type": round(sender_type_component, 1),
            "sender_reputation": round(reputation_component, 1),
            "message_context": round(context_component, 1),
            "impersonation": round(impersonation_component, 1),
            "spam_scam_probability": round(spam_scam_component, 1),
        },
    }