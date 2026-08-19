"""
test_contact_agent_blackbox.py

Black-box test suite for the Contact Agent (agents/contact_agent.py).

WHY "BLACK BOX"
----------------
These tests never import agents.contact_agent or any of the helper
modules under agents/contact/*. They only know what any external caller
of the service knows: the documented HTTP contract exposed by main.py

    POST /analyze-contact
        { sender, body, timestamp?, is_saved_contact?, contact_name? }
        -> 200 JSON matching the response shape documented in
           agents/contact_agent.py's module docstring
        -> 400 if body is empty
        -> 422 if a required field is missing/malformed

    GET /health
        -> { ..., "contact_agent": bool, ... }

Tests only assert on:
  * HTTP status codes
  * the shape/types/domains of the JSON response
  * cross-field consistency that is part of the documented contract
    (e.g. score <-> level <-> verdict mapping described in the code's
    own docstrings)
  * end-to-end behavior for realistic message scenarios (impersonation,
    OTP phishing, prize scams, etc.) described by the "reasons" the
    agent itself is documented to produce

No internal function is called or mocked. If the implementation is
refactored but the HTTP contract stays the same, these tests keep
passing; if the contract breaks, they fail.

PREREQUISITES
--------------
    pip install requests

    Start the backend first, e.g.:
        uvicorn backend.app.main:app --reload --port 8000
    (adjust the module path to wherever your FastAPI `app` actually
    lives in your project)

USAGE
-----
    # against the default http://localhost:8000
    python test_contact_agent_blackbox.py -v

    # against a different host
    python test_contact_agent_blackbox.py --base-url http://localhost:9000 -v
    CONTACT_AGENT_BASE_URL=http://localhost:9000 python test_contact_agent_blackbox.py

    # via pytest (respects the env var, not --base-url)
    CONTACT_AGENT_BASE_URL=http://localhost:8000 pytest test_contact_agent_blackbox.py -v

If the server isn't reachable, or /health reports the contact agent as
unavailable, every test is SKIPPED (not failed) with a clear message.
"""

import os
import random
import string
import sys
import unittest
from typing import Any, Dict, Optional, Tuple

try:
    import requests
except ImportError:  # pragma: no cover
    print("This test suite requires the 'requests' package: pip install requests")
    raise


# ============================================================
# CONFIG
# ============================================================

BASE_URL = os.environ.get("CONTACT_AGENT_BASE_URL", "http://localhost:8000").rstrip("/")
CONTACT_ENDPOINT = "/analyze-contact"
HEALTH_ENDPOINT = "/health"
REQUEST_TIMEOUT = 15  # seconds


# ============================================================
# CONTRACT DOMAINS
# (taken from the documented response shape / docstrings, not from
#  reading internal implementation logic)
# ============================================================

VALID_LEVELS = {"SAFE", "CAUTION", "DANGER"}
VALID_VERDICTS = {"TRUSTED", "LOW_RISK", "CAUTION", "SUSPICIOUS", "HIGH_RISK"}
VALID_CLASSIFICATIONS = {"NORMAL", "SUSPICIOUS", "SPAM", "SCAM"}
VALID_SENDER_TYPES = {
    "PERSONAL_NUMBER", "BUSINESS_NUMBER", "ALPHANUMERIC_SENDER_ID",
    "SHORT_CODE", "SUSPICIOUS", "UNKNOWN",
}
VALID_IMPERSONATION_RISK = {"LOW", "MEDIUM", "HIGH"}
VALID_MODEL_USED = {"trained", "rule_based"}

TOP_LEVEL_KEYS = {
    "is_saved_contact", "contact_name", "level", "score", "confidence",
    "reasons", "short_explanation", "signals",
    "contact", "sender", "sender_reputation", "message_analysis",
    "risk_signals", "impersonation", "trust",
}
SIGNALS_KEYS = {"is_saved_contact", "is_first_contact", "sender_type", "sender_reputation"}
CONTACT_KEYS = {"is_saved_contact", "contact_name"}
SENDER_KEYS = {"normalized", "type", "confidence"}
SENDER_REPUTATION_KEYS = {
    "status", "spam_score", "total_messages", "suspicious_messages",
    "spam_messages", "mongo_available",
}
MESSAGE_ANALYSIS_KEYS = {"classification", "spam_probability", "scam_probability", "model_used"}
RISK_SIGNALS_KEYS = {
    "financial_request", "credential_request", "urgency", "threat",
    "impersonation", "suspicious_link", "secrecy_request",
}
IMPERSONATION_KEYS = {"detected", "claimed_entity", "risk", "reason"}
TRUST_KEYS = {"score", "verdict", "components"}
TRUST_COMPONENT_KEYS = {
    "saved_contact", "sender_type", "sender_reputation",
    "message_context", "impersonation", "spam_scam_probability",
}


# ============================================================
# TEST DATA GENERATORS
# ============================================================

def _random_indian_mobile() -> str:
    """A syntactically valid, unique-ish Indian mobile number for tests
    that need a fresh sender identity (so per-sender state from other
    test runs/tests doesn't bleed in)."""
    first = random.choice("6789")
    rest = "".join(random.choices(string.digits, k=9))
    return "+91" + first + rest


# ============================================================
# SERVER AVAILABILITY (checked once, lazily, and cached)
# ============================================================

_server_status_cache: Dict[str, Any] = {}


def _check_server(base_url: str) -> Tuple[bool, str]:
    try:
        resp = requests.get(base_url + HEALTH_ENDPOINT, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return False, f"could not connect to {base_url}{HEALTH_ENDPOINT}: {exc}"

    if resp.status_code != 200:
        return False, f"{HEALTH_ENDPOINT} returned HTTP {resp.status_code}"

    try:
        data = resp.json()
    except ValueError:
        return False, f"{HEALTH_ENDPOINT} did not return valid JSON"

    if not data.get("contact_agent", False):
        return False, "server is up but reports contact_agent as unavailable in /health"

    return True, "ok"


def get_server_status() -> Tuple[bool, str]:
    if "checked" not in _server_status_cache:
        ok, detail = _check_server(BASE_URL)
        _server_status_cache["checked"] = True
        _server_status_cache["ok"] = ok
        _server_status_cache["detail"] = detail
    return _server_status_cache["ok"], _server_status_cache["detail"]


# ============================================================
# BASE TEST CASE
# ============================================================

class ContactAgentAPITestCase(unittest.TestCase):
    """Common plumbing shared by every black-box test class below."""

    def setUp(self):
        ok, detail = get_server_status()
        if not ok:
            self.skipTest(
                f"Contact Agent API not reachable/healthy at {BASE_URL} ({detail}). "
                "Start the backend and/or set CONTACT_AGENT_BASE_URL, then retry."
            )

    # ---------- request helper ----------

    def post_contact(
        self,
        sender: str,
        body: str,
        is_saved_contact: bool = False,
        contact_name: Optional[str] = None,
        timestamp: Optional[int] = None,
        omit_sender: bool = False,
        omit_body: bool = False,
        **extra: Any,
    ) -> requests.Response:
        payload: Dict[str, Any] = {}
        if not omit_sender:
            payload["sender"] = sender
        if not omit_body:
            payload["body"] = body
        payload["is_saved_contact"] = is_saved_contact
        if contact_name is not None:
            payload["contact_name"] = contact_name
        if timestamp is not None:
            payload["timestamp"] = timestamp
        payload.update(extra)

        return requests.post(
            BASE_URL + CONTACT_ENDPOINT, json=payload, timeout=REQUEST_TIMEOUT
        )

    # ---------- schema / domain assertions ----------

    def assert_valid_contact_response(self, data: Dict[str, Any]) -> None:
        missing = TOP_LEVEL_KEYS - set(data.keys())
        self.assertFalse(missing, f"Response missing top-level keys: {missing}")

        self.assertIsInstance(data["level"], str)
        self.assertIn(data["level"], VALID_LEVELS)

        self.assertIsInstance(data["score"], int)
        self.assertGreaterEqual(data["score"], 0)
        self.assertLessEqual(data["score"], 100)

        self.assertIsInstance(data["confidence"], int)
        self.assertGreaterEqual(data["confidence"], 0)
        self.assertLessEqual(data["confidence"], 100)

        self.assertIsInstance(data["reasons"], list)
        self.assertTrue(all(isinstance(r, str) for r in data["reasons"]))
        self.assertGreater(len(data["reasons"]), 0, "reasons should never be empty")

        self.assertIsInstance(data["short_explanation"], str)
        self.assertTrue(data["short_explanation"].strip(), "short_explanation should not be blank")

        signals = data["signals"]
        self.assertFalse(SIGNALS_KEYS - set(signals.keys()), f"signals missing keys: {SIGNALS_KEYS - set(signals.keys())}")
        self.assertIn(signals["sender_type"], VALID_SENDER_TYPES)

        contact = data["contact"]
        self.assertFalse(CONTACT_KEYS - set(contact.keys()))

        sender = data["sender"]
        self.assertFalse(SENDER_KEYS - set(sender.keys()))
        self.assertIn(sender["type"], VALID_SENDER_TYPES)
        self.assertIsInstance(sender["confidence"], (int, float))
        self.assertGreaterEqual(sender["confidence"], 0.0)
        self.assertLessEqual(sender["confidence"], 1.0)

        rep = data["sender_reputation"]
        self.assertFalse(SENDER_REPUTATION_KEYS - set(rep.keys()))
        self.assertIsInstance(rep["mongo_available"], bool)
        self.assertIsInstance(rep["total_messages"], int)
        self.assertGreaterEqual(rep["total_messages"], 0)

        msg = data["message_analysis"]
        self.assertFalse(MESSAGE_ANALYSIS_KEYS - set(msg.keys()))
        self.assertIn(msg["classification"], VALID_CLASSIFICATIONS)
        self.assertIn(msg["model_used"], VALID_MODEL_USED)
        for prob_key in ("spam_probability", "scam_probability"):
            self.assertGreaterEqual(msg[prob_key], 0.0)
            self.assertLessEqual(msg[prob_key], 1.0)

        risk = data["risk_signals"]
        self.assertFalse(RISK_SIGNALS_KEYS - set(risk.keys()))
        for key in RISK_SIGNALS_KEYS:
            self.assertIsInstance(risk[key], bool, f"risk_signals.{key} should be a bool")

        imp = data["impersonation"]
        self.assertFalse(IMPERSONATION_KEYS - set(imp.keys()))
        self.assertIsInstance(imp["detected"], bool)
        self.assertIn(imp["risk"], VALID_IMPERSONATION_RISK)

        trust = data["trust"]
        self.assertFalse(TRUST_KEYS - set(trust.keys()))
        self.assertIn(trust["verdict"], VALID_VERDICTS)
        self.assertFalse(TRUST_COMPONENT_KEYS - set(trust["components"].keys()))

        # cross-field consistency that IS part of the documented contract:
        # top-level `score`/`level` are derived from `trust.score`/`trust.verdict`.
        self.assertEqual(
            data["score"], trust["score"],
            "top-level score must match trust.score (they're documented as the same value)",
        )
        self.assert_level_matches_verdict(data["level"], trust["verdict"])
        self.assert_verdict_matches_score(trust["score"], trust["verdict"])

    def assert_level_matches_verdict(self, level: str, verdict: str) -> None:
        expected = {
            "TRUSTED": "SAFE",
            "LOW_RISK": "SAFE",
            "CAUTION": "CAUTION",
            "SUSPICIOUS": "DANGER",
            "HIGH_RISK": "DANGER",
        }[verdict]
        self.assertEqual(level, expected, f"level={level!r} inconsistent with verdict={verdict!r}")

    def assert_verdict_matches_score(self, score: int, verdict: str) -> None:
        if score >= 80:
            expected = "TRUSTED"
        elif score >= 60:
            expected = "LOW_RISK"
        elif score >= 40:
            expected = "CAUTION"
        elif score >= 20:
            expected = "SUSPICIOUS"
        else:
            expected = "HIGH_RISK"
        self.assertEqual(verdict, expected, f"score={score} inconsistent with verdict={verdict!r}")


# ============================================================
# 1. RESPONSE CONTRACT / SCHEMA
# ============================================================

class TestResponseContract(ContactAgentAPITestCase):
    """Verifies the shape and internal consistency of a normal 200 response,
    independent of what scenario produced it."""

    def test_health_endpoint_reports_contact_agent(self):
        resp = requests.get(BASE_URL + HEALTH_ENDPOINT, timeout=REQUEST_TIMEOUT)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("contact_agent", data)
        self.assertTrue(data["contact_agent"])

    def test_schema_for_benign_message(self):
        resp = self.post_contact(
            sender=_random_indian_mobile(),
            body="Hey, are we still on for lunch today?",
            is_saved_contact=True,
            contact_name="Priya",
        )
        self.assertEqual(resp.status_code, 200)
        self.assert_valid_contact_response(resp.json())

    def test_schema_for_scam_message(self):
        resp = self.post_contact(
            sender=_random_indian_mobile(),
            body="URGENT: Your account will be suspended. Send your OTP now to avoid penalty.",
            is_saved_contact=False,
        )
        self.assertEqual(resp.status_code, 200)
        self.assert_valid_contact_response(resp.json())

    def test_schema_holds_across_varied_inputs(self):
        scenarios = [
            ("HDFCBK", "Your HDFC Bank account balance is Rs 12,500.", False, None),
            ("56070", "Your OTP is required to complete verification.", False, None),
            (_random_indian_mobile(), "Congratulations! You have won a lucky prize, claim now.", False, None),
            ("VM-AMAZON", "Your Amazon order has been shipped.", True, "Amazon"),
        ]
        for sender, body, saved, name in scenarios:
            with self.subTest(sender=sender, body=body):
                resp = self.post_contact(sender, body, is_saved_contact=saved, contact_name=name)
                self.assertEqual(resp.status_code, 200)
                self.assert_valid_contact_response(resp.json())


# ============================================================
# 2. INPUT VALIDATION / ERROR HANDLING
# ============================================================

class TestInputValidation(ContactAgentAPITestCase):

    def test_empty_body_returns_400(self):
        resp = self.post_contact(sender=_random_indian_mobile(), body="")
        self.assertEqual(resp.status_code, 400)

    def test_whitespace_only_body_returns_400(self):
        resp = self.post_contact(sender=_random_indian_mobile(), body="   \n\t  ")
        self.assertEqual(resp.status_code, 400)

    def test_missing_body_field_returns_422(self):
        resp = self.post_contact(sender=_random_indian_mobile(), body="", omit_body=True)
        self.assertEqual(resp.status_code, 422)

    def test_missing_sender_field_returns_422(self):
        resp = self.post_contact(sender="", body="Hello there", omit_sender=True)
        self.assertEqual(resp.status_code, 422)

    def test_empty_sender_string_degrades_gracefully(self):
        # sender explicitly present but empty -> the agent is documented
        # to fall back to "unknown" rather than error out.
        resp = self.post_contact(sender="", body="Hello, just checking in.")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assert_valid_contact_response(data)
        self.assertEqual(data["sender"]["type"], "UNKNOWN")

    def test_default_is_saved_contact_is_false(self):
        resp = requests.post(
            BASE_URL + CONTACT_ENDPOINT,
            json={"sender": _random_indian_mobile(), "body": "Hi there"},
            timeout=REQUEST_TIMEOUT,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["is_saved_contact"])


# ============================================================
# 3. SENDER CLASSIFICATION BEHAVIOR
# ============================================================

class TestSenderClassification(ContactAgentAPITestCase):

    def test_mobile_number_classified_as_personal(self):
        resp = self.post_contact(_random_indian_mobile(), "Hey, call me when you're free.")
        data = resp.json()
        self.assertEqual(data["sender"]["type"], "PERSONAL_NUMBER")

    def test_short_numeric_code_classified_as_short_code(self):
        resp = self.post_contact("56070", "Your OTP for login is required.")
        data = resp.json()
        self.assertEqual(data["sender"]["type"], "SHORT_CODE")

    def test_alphanumeric_id_classified_correctly(self):
        resp = self.post_contact("HDFCBK", "Your account statement is ready.")
        data = resp.json()
        self.assertEqual(data["sender"]["type"], "ALPHANUMERIC_SENDER_ID")
        self.assertEqual(data["sender"]["normalized"], "HDFCBK")

    def test_malformed_phone_like_sender_flagged_suspicious(self):
        # too many digits to be a real number, but phone-number "shaped"
        resp = self.post_contact("12345678901234", "Hello")
        data = resp.json()
        self.assertIn(data["sender"]["type"], {"SUSPICIOUS", "UNKNOWN"})


# ============================================================
# 4. IMPERSONATION DETECTION
# ============================================================

class TestImpersonationDetection(ContactAgentAPITestCase):

    def test_brand_name_from_personal_number_flags_impersonation(self):
        resp = self.post_contact(
            sender=_random_indian_mobile(),
            body=(
                "HDFC Bank: Your account will be suspended due to KYC issue. "
                "Send your card number and CVV immediately to avoid penalty."
            ),
        )
        data = resp.json()
        self.assertTrue(data["impersonation"]["detected"])
        self.assertEqual(data["impersonation"]["claimed_entity"], "HDFC Bank")
        self.assertIn(data["impersonation"]["risk"], {"MEDIUM", "HIGH"})
        self.assertTrue(data["risk_signals"]["impersonation"])
        self.assertIn(data["level"], {"CAUTION", "DANGER"})

    def test_matching_sender_id_does_not_flag_impersonation(self):
        resp = self.post_contact(
            sender="HDFCBK",
            body="HDFC Bank: Your account balance is Rs 5,000 as of today.",
        )
        data = resp.json()
        self.assertFalse(data["impersonation"]["detected"])
        self.assertEqual(data["impersonation"]["claimed_entity"], "HDFC Bank")
        self.assertFalse(data["risk_signals"]["impersonation"])

    def test_message_naming_no_known_entity_has_no_impersonation(self):
        resp = self.post_contact(_random_indian_mobile(), "See you at 6pm, don't be late!")
        data = resp.json()
        self.assertFalse(data["impersonation"]["detected"])
        self.assertIsNone(data["impersonation"]["claimed_entity"])
        self.assertEqual(data["impersonation"]["risk"], "LOW")

    def test_delivery_brand_impersonation_from_personal_number(self):
        resp = self.post_contact(
            sender=_random_indian_mobile(),
            body="FedEx: Your parcel is held at customs. Pay customs fee now to release delivery.",
        )
        data = resp.json()
        self.assertTrue(data["impersonation"]["detected"])
        self.assertEqual(data["impersonation"]["claimed_entity"], "FedEx")
        self.assertTrue(data["risk_signals"]["delivery_payment_scam"])


# ============================================================
# 5. MESSAGE-CONTENT RISK SIGNALS
# ============================================================

class TestMessageRiskSignals(ContactAgentAPITestCase):

    def test_otp_phishing_triggers_credential_urgency_threat(self):
        resp = self.post_contact(
            sender=_random_indian_mobile(),
            body="URGENT: Your bank account will be suspended. Send your OTP immediately to verify.",
        )
        data = resp.json()
        rs = data["risk_signals"]
        self.assertTrue(rs["credential_request"])
        self.assertTrue(rs["urgency"])
        self.assertTrue(rs["threat"])
        self.assertEqual(data["message_analysis"]["classification"], "SCAM")
        self.assertEqual(data["level"], "DANGER")

    def test_prize_scam_with_shortened_link(self):
        resp = self.post_contact(
            sender=_random_indian_mobile(),
            body="Congratulations! You have won a lucky prize. Claim your reward now: http://bit.ly/claim123",
        )
        data = resp.json()
        rs = data["risk_signals"]
        self.assertTrue(rs["suspicious_link"])
        self.assertIn(data["message_analysis"]["classification"], {"SUSPICIOUS", "SPAM", "SCAM"})

    def test_secrecy_plus_financial_request_is_high_risk(self):
        resp = self.post_contact(
            sender=_random_indian_mobile(),
            body="Don't tell anyone about this. Transfer money to this account right now, it's urgent.",
        )
        data = resp.json()
        rs = data["risk_signals"]
        self.assertTrue(rs["secrecy_request"])
        self.assertTrue(rs["financial_request"])
        self.assertIn(data["level"], {"CAUTION", "DANGER"})

    def test_benign_message_has_no_risk_signals(self):
        resp = self.post_contact(
            sender=_random_indian_mobile(),
            body="Good morning! Hope you have a great day.",
            is_saved_contact=True,
        )
        data = resp.json()
        rs = data["risk_signals"]
        self.assertFalse(any(rs.values()), f"unexpected risk signals for a benign message: {rs}")
        self.assertEqual(data["message_analysis"]["classification"], "NORMAL")

    def test_personal_info_request_flagged(self):
        resp = self.post_contact(
            sender=_random_indian_mobile(),
            body="Please share your Aadhaar number and date of birth to continue processing.",
        )
        data = resp.json()
        self.assertTrue(data["risk_signals"]["personal_info_request"])


# ============================================================
# 6. TRUST SCORING BEHAVIOR (end-to-end, contract-level)
# ============================================================

class TestTrustScoringBehavior(ContactAgentAPITestCase):

    def test_saved_contact_benign_message_scores_higher_than_stranger_scam(self):
        good = self.post_contact(
            sender=_random_indian_mobile(),
            body="Hey, running 10 mins late, see you soon!",
            is_saved_contact=True,
            contact_name="Rohan",
        ).json()

        bad = self.post_contact(
            sender=_random_indian_mobile(),
            body="URGENT: Send your OTP and PIN now or your account will be permanently blocked.",
            is_saved_contact=False,
        ).json()

        self.assertGreater(good["score"], bad["score"])
        self.assertEqual(bad["level"], "DANGER")

    def test_reasons_reflect_saved_contact_status(self):
        saved = self.post_contact(
            _random_indian_mobile(), "Hi!", is_saved_contact=True
        ).json()
        unsaved = self.post_contact(
            _random_indian_mobile(), "Hi!", is_saved_contact=False
        ).json()

        self.assertTrue(any("saved" in r.lower() for r in saved["reasons"]))
        self.assertTrue(any("not in your saved contacts" in r.lower() for r in unsaved["reasons"]))


# ============================================================
# 7. STATEFUL BEHAVIOR (per-sender history / reputation)
# ============================================================

class TestStatefulBehavior(ContactAgentAPITestCase):

    def test_second_message_from_same_sender_is_not_first_contact(self):
        sender = _random_indian_mobile()

        first = self.post_contact(sender, "Hi, this is my first message.").json()
        self.assertTrue(first["signals"]["is_first_contact"])

        second = self.post_contact(sender, "Following up on my earlier message.").json()
        self.assertFalse(second["signals"]["is_first_contact"])

    def test_reputation_history_grows_when_mongo_is_available(self):
        sender = _random_indian_mobile()

        first = self.post_contact(sender, "Hello, quick question for you.").json()
        second = self.post_contact(sender, "Following up on that, any update?").json()

        if not first["sender_reputation"]["mongo_available"]:
            self.skipTest("MongoDB reputation store not available in this environment.")

        self.assertGreaterEqual(
            second["sender_reputation"]["total_messages"],
            first["sender_reputation"]["total_messages"] + 1,
        )


# ============================================================
# 8. ROBUSTNESS / EDGE CASES
# ============================================================

class TestRobustness(ContactAgentAPITestCase):

    def test_handles_unicode_and_emoji(self):
        resp = self.post_contact(
            _random_indian_mobile(),
            "नमस्ते! 🎉 आपका ऑर्डर भेज दिया गया है 📦",
        )
        self.assertEqual(resp.status_code, 200)
        self.assert_valid_contact_response(resp.json())

    def test_handles_very_long_message(self):
        long_body = "This is a normal update. " * 400  # ~10,000 chars
        resp = self.post_contact(_random_indian_mobile(), long_body)
        self.assertEqual(resp.status_code, 200)
        self.assert_valid_contact_response(resp.json())

    def test_handles_regex_special_characters(self):
        resp = self.post_contact(
            _random_indian_mobile(),
            "Price: $$$ ((total)) [50% off]* .*+?^${}()|[]\\ weird^chars",
        )
        self.assertEqual(resp.status_code, 200)
        self.assert_valid_contact_response(resp.json())

    def test_handles_multiple_urls(self):
        resp = self.post_contact(
            _random_indian_mobile(),
            "Check these: http://example.com/a http://bit.ly/xyz https://tinyurl.com/abc123",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["risk_signals"]["suspicious_link"])

    def test_contact_name_with_special_characters_is_accepted(self):
        resp = self.post_contact(
            _random_indian_mobile(),
            "Hi there!",
            is_saved_contact=True,
            contact_name="O'Brien & Sohne <Team>",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["contact_name"], "O'Brien & Sohne <Team>")


# ============================================================
# ENTRYPOINT
# ============================================================

def _build_arg_parser():
    import argparse
    parser = argparse.ArgumentParser(
        description="Black-box tests for the Contact Agent HTTP API.",
        add_help=True,
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help=f"Base URL of the running backend (default: env CONTACT_AGENT_BASE_URL or {BASE_URL})",
    )
    return parser


if __name__ == "__main__":
    arg_parser = _build_arg_parser()
    known_args, remaining_argv = arg_parser.parse_known_args()

    if known_args.base_url:
        BASE_URL = known_args.base_url.rstrip("/")

    print(f"Running Contact Agent black-box tests against: {BASE_URL}\n")

    unittest.main(argv=[sys.argv[0]] + remaining_argv, verbosity=2)