"""
agents/contact/risk_analyzer.py

Explainable message-content risk analysis for the Contact Agent:

    1. detect_signals()      - regex/keyword based structured risk signals
    2. MessageClassifier     - NORMAL / SUSPICIOUS / SPAM / SCAM
                                probability estimate, backed by an
                                optional trained scikit-learn model with
                                an always-available rule-based fallback.

This is intentionally separate from url_agent.py's LLM-based phishing
detection - this module is fast, offline, and does not call an external
API, so it can run on every single message without added latency/cost.
"""

import os
import re
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("scamshield.contact.risk_analyzer")


# ============================================================
# STRUCTURED SIGNAL DETECTION
# ============================================================

_FINANCIAL_PATTERNS = [
    r"\bsend\s+(?:me\s+)?(?:rs\.?|inr|₹|\$)?\s?\d",
    r"\btransfer\b.{0,20}\b(money|amount|fund)",
    r"\bupi\b",
    r"\bbank\s+account\b",
    r"\b(pay|payment)\s+(?:now|immediately|urgently)\b",
    r"\bdonat(e|ion)\b",
    r"\bloan\b",
    r"\bwire\s+transfer\b",
    r"₹\s?\d",
    r"\brs\.?\s?\d",
]

_CREDENTIAL_PATTERNS = [
    r"\botp\b",
    r"\bpassword\b",
    r"\bpin\b",
    r"\bcvv\b",
    r"\bcard\s+number\b",
    r"\blogin\s+details\b",
    r"\bverification\s+code\b",
]

_URGENCY_PATTERNS = [
    r"\burgent(ly)?\b",
    r"\bimmediately\b",
    r"\bright\s+now\b",
    r"\bwithin\s+\d+\s*(hour|hr|minute|min)s?\b",
    r"\blast\s+chance\b",
    r"\bact\s+now\b",
    r"\bexpir(e|es|ing|y)\b",
]

_THREAT_PATTERNS = [
    r"\bblocked\b",
    r"\bsuspend(ed)?\b",
    r"\blegal\s+action\b",
    r"\bwill\s+be\s+closed\b",
    r"\bpenalt(y|ies)\b",
    r"\barrest(ed)?\b",
    r"\baccount\s+will\s+be\s+(deactivated|terminated|frozen)\b",
]

_SECRECY_PATTERNS = [
    r"\bdon'?t\s+tell\s+anyone\b",
    r"\bdon'?t\s+call\s+(me|anyone)\b",
    r"\bkeep\s+this\s+(confidential|secret|between us)\b",
    r"\bthis\s+is\s+between\s+us\b",
    r"\bdo\s+not\s+inform\b",
]

_PERSONAL_INFO_PATTERNS = [
    r"\baadhaar?\b",
    r"\bpan\s+card\b",
    r"\bdate\s+of\s+birth\b",
    r"\bssn\b",
    r"\bpassport\s+number\b",
    r"\bhome\s+address\b",
]

_PRIZE_PATTERNS = [
    r"\byou\s+(have\s+)?won\b",
    r"\bcongratulations\b.{0,30}\bwon\b",
    r"\blucky\s+winner\b",
    r"\bclaim\s+(your\s+)?(prize|reward|gift)\b",
    r"\bfree\s+gift\b",
]

_DELIVERY_PAYMENT_SCAM_PATTERNS = [
    r"\bcustoms\s+(fee|duty)\b",
    r"\bdelivery\s+fee\b",
    r"\bpay\s+to\s+release\b",
    r"\boutstanding\s+payment\b",
    r"\bredelivery\s+fee\b",
]

_URL_PATTERN = r"https?://\S+"

_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at",
}


def _any_match(patterns: List[str], text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def _has_suspicious_link(text: str) -> Tuple[bool, List[str]]:
    urls = re.findall(_URL_PATTERN, text, re.IGNORECASE)

    if not urls:
        return False, []

    # Any link is treated as a signal; the caller/trust score decides how
    # much weight to give it based on other context.
    return True, urls


def detect_signals(message: str) -> Dict[str, Any]:
    """
    Returns structured, explainable signals plus a "reasons" list in
    plain language. Every boolean here is evidence-based (a regex/keyword
    hit), never a guess.
    """

    text = message or ""

    financial_request = _any_match(_FINANCIAL_PATTERNS, text)
    credential_request = _any_match(_CREDENTIAL_PATTERNS, text)
    urgency = _any_match(_URGENCY_PATTERNS, text)
    threat = _any_match(_THREAT_PATTERNS, text)
    secrecy_request = _any_match(_SECRECY_PATTERNS, text)
    personal_info_request = _any_match(_PERSONAL_INFO_PATTERNS, text)
    prize_scam = _any_match(_PRIZE_PATTERNS, text)
    delivery_payment_scam = _any_match(_DELIVERY_PAYMENT_SCAM_PATTERNS, text)
    suspicious_link, urls = _has_suspicious_link(text)
    uses_shortener = any(d in u.lower() for u in urls for d in _SHORTENER_DOMAINS)

    reasons: List[str] = []

    if financial_request:
        reasons.append("Message requests money or a financial transaction")
    if credential_request:
        reasons.append("Message asks for an OTP, password, PIN, or similar credential")
    if urgency:
        reasons.append("Message uses urgent or time-pressured language")
    if threat:
        reasons.append("Message contains threatening language (e.g. account blocked/suspended)")
    if secrecy_request:
        reasons.append("Message asks you to keep it secret or not tell/call anyone")
    if personal_info_request:
        reasons.append("Message asks for sensitive personal information")
    if prize_scam:
        reasons.append("Message references winning a prize or reward")
    if delivery_payment_scam:
        reasons.append("Message references a delivery or customs fee that must be paid")
    if suspicious_link:
        reasons.append(
            "Message contains a link" + (" using a URL shortener" if uses_shortener else "")
        )

    return {
        "financial_request": financial_request,
        "credential_request": credential_request,
        "urgency": urgency,
        "threat": threat,
        "secrecy_request": secrecy_request,
        "personal_info_request": personal_info_request,
        "prize_scam": prize_scam,
        "delivery_payment_scam": delivery_payment_scam,
        "suspicious_link": suspicious_link,
        "urls": urls,
        "reasons": reasons,
    }


# ============================================================
# MESSAGE CLASSIFICATION (NORMAL / SUSPICIOUS / SPAM / SCAM)
# ============================================================
#
# Architecture:
#   - If a trained scikit-learn model is found at MODEL_PATH, use it.
#   - Otherwise, fall back to a transparent rule-based scorer built from
#     detect_signals() above. This keeps the interface identical either
#     way, so a trained model can be dropped in later with no other code
#     changes.
#
# No model is shipped and no accuracy numbers are fabricated - the
# rule-based fallback is honest about being a heuristic.
# ============================================================

MODEL_PATH = os.environ.get("CONTACT_MODEL_PATH", "models/contact_message_classifier.joblib")


class MessageClassifier:
    """
    classify(message, signals) -> {
        "classification": "NORMAL" | "SUSPICIOUS" | "SPAM" | "SCAM",
        "spam_probability": 0.0-1.0,
        "scam_probability": 0.0-1.0,
        "model_used": "trained" | "rule_based",
    }
    """

    def __init__(self, model_path: str = MODEL_PATH):
        self.model_path = model_path
        self._pipeline = None
        self._model_loaded = False
        self._load_model()

    def _load_model(self) -> None:
        if not os.path.exists(self.model_path):
            logger.info(
                "No trained classifier found at %s - using rule-based fallback.",
                self.model_path,
            )
            return

        try:
            import joblib  # ships with scikit-learn; imported lazily

            self._pipeline = joblib.load(self.model_path)
            self._model_loaded = True
            logger.info("Loaded trained contact message classifier from %s", self.model_path)

        except Exception as e:
            logger.error(
                "Failed to load trained classifier (%s) - using rule-based fallback.", str(e)
            )
            self._pipeline = None
            self._model_loaded = False

    def classify(self, message: str, signals: Dict[str, Any]) -> Dict[str, Any]:
        if self._model_loaded and self._pipeline is not None:
            try:
                return self._classify_with_model(message)
            except Exception as e:
                logger.error(
                    "Trained classifier inference failed (%s) - falling back to rules.", str(e)
                )

        return self._classify_with_rules(signals)

    def _classify_with_model(self, message: str) -> Dict[str, Any]:
        proba = self._pipeline.predict_proba([message])[0]
        classes = list(self._pipeline.classes_)

        proba_map = dict(zip(classes, proba))
        classification = max(proba_map, key=proba_map.get)

        return {
            "classification": classification,
            "spam_probability": round(float(proba_map.get("SPAM", 0.0)), 3),
            "scam_probability": round(float(proba_map.get("SCAM", 0.0)), 3),
            "model_used": "trained",
        }

    def _classify_with_rules(self, signals: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transparent, weighted heuristic. Not a substitute for a trained
        model, but gives a reasonable, explainable estimate until one
        exists.
        """

        scam_score = 0.0
        spam_score = 0.0

        if signals.get("credential_request"):
            scam_score += 0.30
        if signals.get("financial_request"):
            scam_score += 0.30
            spam_score += 0.10
        if signals.get("threat"):
            # A threat (arrest, legal action, account suspension) is
            # itself a classic scam opener designed to induce panic
            # before the "ask" even arrives - weight it more heavily on
            # its own, not just as a minor contributor.
            scam_score += 0.30
        if signals.get("secrecy_request"):
            scam_score += 0.20
        if signals.get("urgency"):
            scam_score += 0.15
            spam_score += 0.05
        if signals.get("prize_scam"):
            scam_score += 0.15
            spam_score += 0.25
        if signals.get("delivery_payment_scam"):
            scam_score += 0.20
        if signals.get("personal_info_request"):
            scam_score += 0.15
        if signals.get("suspicious_link"):
            scam_score += 0.15
            spam_score += 0.10

        # ----------------------------------------------------
        # Combo bonuses for well-known scam templates.
        # ----------------------------------------------------
        # A single weak signal in isolation (e.g. "urgent" on its own)
        # is common in ordinary messages and shouldn't spike the score.
        # But specific PAIRS of signals together are the actual
        # fingerprint of common scam scripts, and should be treated as
        # much stronger evidence than the sum of their parts:
        #   - "send me money" + urgency          -> emergency-money scam
        #     ("I've had an accident, send 20000 now")
        #   - threat + urgency                    -> panic/arrest scam
        #     ("you are arrested... act now")
        #   - threat + financial_request          -> extortion / fake-fine scam
        #   - credential_request + urgency         -> OTP/credential phishing
        if signals.get("financial_request") and signals.get("urgency"):
            scam_score += 0.20
        if signals.get("threat") and signals.get("urgency"):
            scam_score += 0.15
        if signals.get("threat") and signals.get("financial_request"):
            scam_score += 0.20
        if signals.get("credential_request") and signals.get("urgency"):
            scam_score += 0.15

        scam_probability = max(0.0, min(1.0, scam_score))
        spam_probability = max(0.0, min(1.0, spam_score))

        # Thresholds lowered from (0.55 / 0.25) - the previous bar meant
        # a message needed 2-3 simultaneous signals just to leave
        # NORMAL, so common single/double-signal scams (a bare threat,
        # or "send money" + urgency) were being classified as NORMAL or
        # only mildly SUSPICIOUS.
        if scam_probability >= 0.45:
            classification = "SCAM"
        elif spam_probability >= 0.5 and scam_probability < 0.35:
            classification = "SPAM"
        elif scam_probability >= 0.20 or spam_probability >= 0.20:
            classification = "SUSPICIOUS"
        else:
            classification = "NORMAL"

        return {
            "classification": classification,
            "spam_probability": round(spam_probability, 3),
            "scam_probability": round(scam_probability, 3),
            "model_used": "rule_based",
        }


_classifier_singleton: Optional[MessageClassifier] = None


def get_classifier() -> MessageClassifier:
    global _classifier_singleton
    if _classifier_singleton is None:
        _classifier_singleton = MessageClassifier()
    return _classifier_singleton