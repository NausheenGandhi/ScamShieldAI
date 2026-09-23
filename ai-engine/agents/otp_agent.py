"""
otp_agent.py

OTP Agent for SMS scam detection.

Responsibilities:
    1. Receive the sanitized SMS from Android.
    2. Use Groq LLM to detect the INTENT of the SMS.
    3. Use Android context as additional signals.
    4. Pass LLM intent + local signals to the Risk Engine.
    5. Return the final OTP security verdict.

IMPORTANT PRIVACY RULE:
    The actual OTP must NEVER reach this agent.

Example:

    Original SMS:
        "Your OTP is 482193. Give me the OTP immediately."

    Android sanitization:
        "Your OTP is [OTP]. Give me the OTP immediately."

    This agent receives only:
        "Your OTP is [OTP]. Give me the OTP immediately."
"""
import re
from typing import Dict, Any, Optional

from utils.groq_client import groq_chat_json

from prompts.otp_prompts import OTP_INTENT_PROMPT

from risk_engine import calculate_risk

# ============================================================
# OTP DETECTION + SANITIZATION
# ============================================================

def sanitize_otp_message(message: str) -> tuple[str, bool]:
    """
    Detect OTP-like numeric codes locally and replace them
    with [OTP] before any LLM processing.

    The actual OTP is NEVER sent to Groq and is NEVER returned.
    """

    if not message:
        return message, False

    # Common OTP formats:
    # 123456
    # 1234
    # 12345678
    otp_pattern = r"\b\d{4,8}\b"

    otp_match = re.search(otp_pattern, message)

    if not otp_match:
        # Already sanitized message
        return message, "[OTP]" in message

    # Replace the actual OTP immediately
    sanitized_message = re.sub(
        otp_pattern,
        "[OTP]",
        message
    )

    return sanitized_message, True
# ============================================================
# LLM INTENT DETECTION
# ============================================================

def detect_otp_intent(
    message: str
) -> Dict[str, Any]:
    """
    Uses Groq to determine the intent of a sanitized SMS.

    The actual OTP is NEVER sent to the LLM.
    """

    # Safety layer:
    # Even if raw SMS accidentally reaches this function,
    # sanitize it before sending anything to Groq.
    sanitized_message, otp_detected = sanitize_otp_message(message)

    prompt = OTP_INTENT_PROMPT.format(
        sms_text=sanitized_message
    )

    try:

        result = groq_chat_json(
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_tokens=500,
        )

        result = validate_llm_result(result)

        # Local detection is authoritative for OTP presence.
        # The LLM only determines intent.
        result["is_otp"] = otp_detected or result.get("is_otp", False)

        return result

    except Exception as e:

        print(
            "OTP Groq analysis failed:",
            str(e)
        )

        return {
            "is_otp": otp_detected,
            "intent": "NORMAL_OTP" if otp_detected else "NON_OTP",
            "sharing_request": False,
            "third_party_request": False,
            "urgency": False,
            "threat": False,
            "phishing": False,
            "possible_unrequested": False,
            "confidence": "low",
            "reason": "Unable to perform LLM intent analysis.",
        }


# ============================================================
# VALIDATE LLM RESULT
# ============================================================

def validate_llm_result(
    result: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Validates and normalizes the JSON returned by Groq.
    """

    allowed_intents = {

        "NORMAL_OTP",

        "OTP_SHARING_REQUEST",

        "UNREQUESTED_OTP",

        "OTP_PHISHING",

        "OTP_THREAT",

        "OTP_CUSTOMER_CARE_SCAM",

        "NON_OTP",
    }


    # --------------------------------------------------------
    # Handle malformed Groq response
    # --------------------------------------------------------

    if not isinstance(
        result,
        dict
    ):

        return {

            "is_otp": False,

            "intent": "NON_OTP",

            "sharing_request": False,

            "third_party_request": False,

            "urgency": False,

            "threat": False,

            "phishing": False,

            "possible_unrequested": False,

            "confidence": "low",

            "reason":
                "Invalid LLM response.",
        }


    # --------------------------------------------------------
    # Intent
    # --------------------------------------------------------

    intent = result.get(
        "intent",
        "NON_OTP"
    )


    if intent not in allowed_intents:

        intent = "NON_OTP"


    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    confidence = result.get(
        "confidence",
        "low"
    )


    if isinstance(
        confidence,
        str
    ):

        confidence = confidence.lower()

        if confidence not in {
            "low",
            "medium",
            "high"
        }:

            confidence = "low"


    # --------------------------------------------------------
    # Return normalized result
    # --------------------------------------------------------

    return {

        "is_otp":
            bool(
                result.get(
                    "is_otp",
                    False
                )
            ),

        "intent":
            intent,

        "sharing_request":
            bool(
                result.get(
                    "sharing_request",
                    False
                )
            ),

        "third_party_request":
            bool(
                result.get(
                    "third_party_request",
                    False
                )
            ),

        "urgency":
            bool(
                result.get(
                    "urgency",
                    False
                )
            ),

        "threat":
            bool(
                result.get(
                    "threat",
                    False
                )
            ),

        "phishing":
            bool(
                result.get(
                    "phishing",
                    False
                )
            ),

        "possible_unrequested":
            bool(
                result.get(
                    "possible_unrequested",
                    False
                )
            ),

        "confidence":
            confidence,

        "reason":
            str(
                result.get(
                    "reason",
                    ""
                )
            ),
    }


# ============================================================
# LOCAL SIGNALS
# ============================================================

def is_plain_mobile_sender(
    sender: str
) -> bool:
    """
    Determines whether the sender looks like a plain
    mobile number.

    This is LOCAL/SIGNAL processing.

    It is not used to determine the semantic intent.
    """

    if not sender:

        return False


    clean_sender = (
        sender
        .replace("+", "")
        .replace("-", "")
        .replace(" ", "")
        .replace("(", "")
        .replace(")", "")
    )


    return (
        clean_sender.isdigit()
        and len(clean_sender) >= 10
    )


# ============================================================
# MAIN OTP AGENT
# ============================================================

def analyze_otp(
    sender: str,
    message: str,
    expected_otp: Optional[bool] = False,
    foreground_app: str = "",
    screen_unlocked: bool = True,
) -> Dict[str, Any]:

    # ========================================================
    # 1. OTP DETECTION + SANITIZATION
    # ========================================================

    sanitized_message, has_otp = sanitize_otp_message(message)

    # ========================================================
    # 2. URL PLACEHOLDER
    # ========================================================

    has_url = (
        "[URL]" in sanitized_message
    )

    # ========================================================
    # 3. SENDER SIGNAL
    # ========================================================

    plain_mobile_sender = is_plain_mobile_sender(
        sender
    )

    # ========================================================
    # 4. LLM INTENT DETECTION
    # ========================================================

    llm_result = detect_otp_intent(
        sanitized_message
    )

    # Make sure local OTP detection is authoritative.
    llm_result["is_otp"] = has_otp or llm_result.get(
        "is_otp",
        False
    )

    # ========================================================
    # 5. RISK ENGINE
    # ========================================================

    risk_result = calculate_risk(
        llm_result=llm_result,
        has_otp=has_otp,
        has_url=has_url,
        plain_mobile_sender=plain_mobile_sender,
        foreground_app=foreground_app,
        screen_unlocked=screen_unlocked,
        expected_otp=expected_otp,
    )

    # ========================================================
    # 6. FINAL RESULT
    # ========================================================

    return {
        "otp_detected": has_otp,

        # NEVER return actual OTP
        "otp_code": None,

        "intent": llm_result.get(
            "intent",
            "NON_OTP"
        ),

        "llm_reason": llm_result.get(
            "reason",
            ""
        ),

        "llm_confidence": llm_result.get(
            "confidence",
            "low"
        ),

        "level": risk_result.get(
            "level",
            "SAFE"
        ),

        "score": risk_result.get(
            "score",
            0
        ),

        "confidence": risk_result.get(
            "confidence",
            0
        ),

        "reasons": risk_result.get(
            "reasons",
            []
        ),

        "signals": {
            "otp_detected": has_otp,

            "otp_code_detected": has_otp,

            "possible_unrequested": llm_result.get(
                "possible_unrequested",
                False
            ),

            "sharing_request": llm_result.get(
                "sharing_request",
                False
            ),

            "third_party_request": llm_result.get(
                "third_party_request",
                False
            ),

            "plain_mobile_sender": plain_mobile_sender,

            "has_url": has_url,

            "urgency": llm_result.get(
                "urgency",
                False
            ),

            "threat": llm_result.get(
                "threat",
                False
            ),

            "phishing": llm_result.get(
                "phishing",
                False
            ),

            "repeated_otp": False,

            "expected_otp": expected_otp,

            "foreground_app": foreground_app,

            "screen_unlocked": screen_unlocked,
        },

        "privacy": {
            "otp_sent_to_llm": False,
            "otp_stored_by_agent": False,
            "otp_returned_by_agent": False,
            "sanitized_input": True,
        },
    }
