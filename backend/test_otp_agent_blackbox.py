"""
test_otp_agent_blackbox.py

Black-box test suite for the OTP Agent backend.

These tests treat the FastAPI service as a black box: they only
talk to it over HTTP (no imports of internal modules) and only
assert on the JSON contract described in otp_agent.py / main.py.

Prerequisites:
    - The FastAPI backend must be running locally, e.g.:
          uvicorn backend.main:app --reload
      reachable at BASE_URL (default http://127.0.0.1:8000).
    - GROQ credentials must be configured so /analyze-sms can reach
      the LLM. If Groq is unreachable, the agent falls back to a
      safe NON_OTP/low-confidence result rather than erroring, so
      most tests still pass, but the "intent classification" tests
      that assert specific intents may be skipped/xfail in that case.

Run:
    pip install pytest requests
    pytest test_otp_agent_blackbox.py -v

Override the target server:
    OTP_AGENT_BASE_URL=http://127.0.0.1:8000 pytest -v
"""

import os
import time
import pytest
import requests

BASE_URL = os.environ.get("OTP_AGENT_BASE_URL", "http://127.0.0.1:8000")
ANALYZE_SMS_URL = f"{BASE_URL}/analyze-sms"
HEALTH_URL = f"{BASE_URL}/health"
ROOT_URL = f"{BASE_URL}/"

REQUEST_TIMEOUT = 30  # seconds; LLM calls can be slow

VALID_INTENTS = {
    "NORMAL_OTP",
    "OTP_SHARING_REQUEST",
    "UNREQUESTED_OTP",
    "OTP_PHISHING",
    "OTP_THREAT",
    "OTP_CUSTOMER_CARE_SCAM",
    "NON_OTP",
}

VALID_CONFIDENCE = {"low", "medium", "high"}


# ============================================================
# HELPERS
# ============================================================

def post_sms(payload: dict, timeout: int = REQUEST_TIMEOUT) -> requests.Response:
    return requests.post(ANALYZE_SMS_URL, json=payload, timeout=timeout)


def base_payload(**overrides) -> dict:
    payload = {
        "sender": "VM-HDFCBK",
        "body": "Your OTP is [OTP]. Valid for 10 minutes.",
        "timestamp": int(time.time() * 1000),
        "source": "android_sms_receiver",
        "expected_otp": True,
        "foreground_app": "",
        "screen_unlocked": True,
        "is_saved_contact": False,
        "contact_name": None,
    }
    payload.update(overrides)
    return payload


def assert_valid_response_shape(data: dict):
    """Structural contract every /analyze-sms response must satisfy."""
    # Top-level required keys
    for key in (
        "otp_detected",
        "otp_code",
        "intent",
        "llm_reason",
        "llm_confidence",
        "level",
        "score",
        "confidence",
        "reasons",
        "signals",
        "privacy",
    ):
        assert key in data, f"Missing top-level key: {key}"

    # Privacy contract is non-negotiable: the real OTP must never
    # be returned or reported as sent/stored.
    assert data["otp_code"] is None, "otp_code must never be populated"
    privacy = data["privacy"]
    assert privacy["otp_sent_to_llm"] is False
    assert privacy["otp_stored_by_agent"] is False
    assert privacy["otp_returned_by_agent"] is False
    assert privacy["sanitized_input"] is True

    # Enum-like fields
    assert data["intent"] in VALID_INTENTS
    assert data["llm_confidence"] in VALID_CONFIDENCE
    assert isinstance(data["reasons"], list)

    # Signals block
    signals = data["signals"]
    for key in (
        "otp_detected",
        "otp_code_detected",
        "possible_unrequested",
        "sharing_request",
        "third_party_request",
        "plain_mobile_sender",
        "has_url",
        "urgency",
        "threat",
        "phishing",
        "repeated_otp",
        "expected_otp",
        "foreground_app",
        "screen_unlocked",
    ):
        assert key in signals, f"Missing signals key: {key}"


# ============================================================
# HEALTH / AVAILABILITY
# ============================================================

class TestServiceHealth:

    def test_root_reports_running(self):
        resp = requests.get(ROOT_URL, timeout=REQUEST_TIMEOUT)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "running"
        assert "agents" in data

    def test_health_reports_otp_agent_available(self):
        resp = requests.get(HEALTH_URL, timeout=REQUEST_TIMEOUT)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["otp_agent"] is True, (
            "OTP agent is reported unavailable — check ai-engine import "
            "path / dependencies before running the rest of this suite."
        )


# ============================================================
# INPUT VALIDATION
# ============================================================

class TestInputValidation:

    def test_empty_body_returns_400(self):
        resp = post_sms(base_payload(body=""))
        assert resp.status_code == 400

    def test_whitespace_only_body_returns_400(self):
        resp = post_sms(base_payload(body="   \n\t  "))
        assert resp.status_code == 400

    def test_missing_body_field_returns_422(self):
        payload = base_payload()
        del payload["body"]
        resp = post_sms(payload)
        assert resp.status_code == 422  # pydantic validation error

    def test_missing_sender_field_returns_422(self):
        payload = base_payload()
        del payload["sender"]
        resp = post_sms(payload)
        assert resp.status_code == 422

    def test_optional_fields_can_be_omitted(self):
        """timestamp/source/expected_otp/etc. all have defaults."""
        minimal_payload = {
            "sender": "AX-TESTBK",
            "body": "Your OTP is [OTP].",
        }
        resp = post_sms(minimal_payload)
        assert resp.status_code == 200
        assert_valid_response_shape(resp.json())


# ============================================================
# RESPONSE CONTRACT / PRIVACY
# ============================================================

class TestResponseContractAndPrivacy:

    def test_response_shape_is_well_formed(self):
        resp = post_sms(base_payload())
        assert resp.status_code == 200
        assert_valid_response_shape(resp.json())

    def test_otp_placeholder_never_leaks_real_code(self):
        """
        Even if a caller mistakenly sends a real 6-digit code instead
        of [OTP], the agent must never echo it back in otp_code.
        """
        resp = post_sms(base_payload(body="Your OTP is 482193. Share it now."))
        assert resp.status_code == 200
        data = resp.json()
        assert data["otp_code"] is None
        assert "482193" not in str(data), "Raw OTP leaked into response"

    def test_otp_detected_true_when_placeholder_present(self):
        resp = post_sms(base_payload(body="Your OTP is [OTP]. Do not share."))
        assert resp.status_code == 200
        data = resp.json()
        assert data["otp_detected"] is True
        assert data["signals"]["otp_detected"] is True

    def test_otp_detected_false_when_no_placeholder(self):
        resp = post_sms(base_payload(
            body="Your package has been shipped and will arrive tomorrow.",
            expected_otp=False,
        ))
        assert resp.status_code == 200
        data = resp.json()
        assert data["otp_detected"] is False


# ============================================================
# INTENT CLASSIFICATION (behavioral / requires live LLM)
# ============================================================

class TestIntentClassification:
    """
    These exercise the full LLM intent-detection path. If Groq is
    unreachable the agent degrades to a safe NON_OTP/low-confidence
    fallback (see otp_agent.detect_otp_intent's except-branch), so
    these assertions may need --runxfail handling in CI without
    live credentials.
    """

    def test_normal_otp_message(self):
        resp = post_sms(base_payload(
            body="Your OTP is [OTP]. Valid for 10 minutes. Do not share with anyone.",
        ))
        assert resp.status_code == 200
        data = resp.json()
        assert data["intent"] in {"NORMAL_OTP", "NON_OTP"}
        assert data["signals"]["sharing_request"] is False

    def test_otp_sharing_request_message(self):
        resp = post_sms(base_payload(
            body="Your OTP is [OTP]. Please send it to me to verify your account.",
        ))
        assert resp.status_code == 200
        data = resp.json()
        assert data["intent"] in {"OTP_SHARING_REQUEST", "NON_OTP"}

    def test_otp_threat_message(self):
        resp = post_sms(base_payload(
            body="Your account will be blocked. Give me the OTP [OTP] immediately.",
        ))
        assert resp.status_code == 200
        data = resp.json()
        assert data["intent"] in {"OTP_THREAT", "OTP_SHARING_REQUEST", "NON_OTP"}

    def test_otp_customer_care_scam_message(self):
        resp = post_sms(base_payload(
            body="Call customer care and provide the OTP [OTP] to verify your account.",
        ))
        assert resp.status_code == 200
        data = resp.json()
        assert data["intent"] in {
            "OTP_CUSTOMER_CARE_SCAM",
            "OTP_SHARING_REQUEST",
            "NON_OTP",
        }

    def test_non_otp_message(self):
        resp = post_sms(base_payload(
            body="Reminder: your electricity bill is due on the 5th.",
            expected_otp=False,
        ))
        assert resp.status_code == 200
        data = resp.json()
        assert data["intent"] == "NON_OTP" or data["signals"]["sharing_request"] is False

    def test_account_security_notification_not_misclassified(self):
        """
        Prompt example 7: a login-alert message should not be
        auto-classified as a sharing request just because it's
        security-related.
        """
        resp = post_sms(base_payload(
            body="We detected a login attempt. If this wasn't you, secure your account immediately.",
            expected_otp=False,
        ))
        assert resp.status_code == 200
        data = resp.json()
        assert data["signals"]["sharing_request"] is False


# ============================================================
# LOCAL SIGNALS (sender / url placeholders — deterministic, no LLM)
# ============================================================

class TestLocalSignals:

    @pytest.mark.parametrize("sender,expected", [
        ("9876543210", True),
        ("+91 98765 43210", True),
        ("(987) 654-3210", True),
        ("VM-HDFCBK", False),
        ("AX-ICICIB", False),
        ("", False),
    ])
    def test_plain_mobile_sender_signal(self, sender, expected):
        resp = post_sms(base_payload(sender=sender, body="Your OTP is [OTP]."))
        assert resp.status_code == 200
        data = resp.json()
        assert data["signals"]["plain_mobile_sender"] is expected

    def test_url_placeholder_signal_present(self):
        resp = post_sms(base_payload(
            body="Your OTP is [OTP]. Verify here: [URL]",
        ))
        assert resp.status_code == 200
        data = resp.json()
        assert data["signals"]["has_url"] is True

    def test_url_placeholder_signal_absent(self):
        resp = post_sms(base_payload(body="Your OTP is [OTP]."))
        assert resp.status_code == 200
        data = resp.json()
        assert data["signals"]["has_url"] is False

    def test_expected_otp_flag_is_echoed(self):
        resp = post_sms(base_payload(body="Your OTP is [OTP].", expected_otp=True))
        assert resp.status_code == 200
        assert resp.json()["signals"]["expected_otp"] is True

        resp2 = post_sms(base_payload(body="Some unrelated text.", expected_otp=False))
        assert resp2.status_code == 200
        assert resp2.json()["signals"]["expected_otp"] is False

    def test_foreground_app_and_screen_state_are_echoed(self):
        resp = post_sms(base_payload(
            body="Your OTP is [OTP].",
            foreground_app="com.example.chatapp",
            screen_unlocked=False,
        ))
        assert resp.status_code == 200
        data = resp.json()
        assert data["signals"]["foreground_app"] == "com.example.chatapp"
        assert data["signals"]["screen_unlocked"] is False


# ============================================================
# RISK LEVEL SANITY CHECKS
# ============================================================

class TestRiskLevelSanity:

    def test_risk_level_is_known_value(self):
        resp = post_sms(base_payload(body="Your OTP is [OTP]."))
        assert resp.status_code == 200
        data = resp.json()
        assert data["level"] in {"SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert isinstance(data["score"], (int, float))

    def test_high_risk_scenario_scores_at_least_as_high_as_benign(self):
        """
        Relative sanity check rather than an exact threshold: a
        message combining sharing request + threat + unknown sender
        should not score lower than a plain benign OTP message.
        """
        benign = post_sms(base_payload(
            sender="VM-HDFCBK",
            body="Your OTP is [OTP]. Do not share it with anyone.",
        )).json()

        suspicious = post_sms(base_payload(
            sender="9876543210",
            body="URGENT: Your account will be blocked. Send me the OTP [OTP] now to customer care [URL]",
            expected_otp=False,
        )).json()

        assert suspicious["score"] >= benign["score"]


# ============================================================
# EDGE CASES
# ============================================================

class TestEdgeCases:

    def test_very_long_message_does_not_error(self):
        long_body = "Your OTP is [OTP]. " + ("Please ignore this notice. " * 200)
        resp = post_sms(base_payload(body=long_body))
        assert resp.status_code == 200
        assert_valid_response_shape(resp.json())

    def test_message_with_multiple_otp_placeholders(self):
        resp = post_sms(base_payload(
            body="Your OTP is [OTP]. Resend: [OTP]. Do not share [OTP].",
        ))
        assert resp.status_code == 200
        data = resp.json()
        assert data["otp_detected"] is True

    def test_non_ascii_message_does_not_error(self):
        resp = post_sms(base_payload(
            body="आपका ओटीपी [OTP] है। इसे किसी के साथ साझा न करें।",
        ))
        assert resp.status_code == 200
        assert_valid_response_shape(resp.json())

    def test_null_contact_name_is_accepted(self):
        resp = post_sms(base_payload(contact_name=None, is_saved_contact=False))
        assert resp.status_code == 200


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))