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

from typing import Dict, Any

from utils.groq_client import groq_chat_json

from prompts.otp_prompts import OTP_INTENT_PROMPT

from risk_engine import calculate_risk


# ============================================================
# LLM INTENT DETECTION
# ============================================================

def detect_otp_intent(
    message: str
) -> Dict[str, Any]:
    """
    Uses Groq to determine the intent of a sanitized SMS.

    The LLM does NOT receive the actual OTP.
    """

    # --------------------------------------------------------
    # Extra safety check
    # --------------------------------------------------------
    #
    # If Android failed to sanitize an OTP and the message
    # contains [OTP], we still don't attempt to extract it here.
    #
    # OTP extraction belongs to Android/local processing.
    # --------------------------------------------------------

    prompt = OTP_INTENT_PROMPT.format(
        sms_text=message
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

        return validate_llm_result(
            result
        )

    except Exception as e:

        print(
            "OTP Groq analysis failed:",
            str(e)
        )

        # Safe fallback.
        return {

            "is_otp":
                "[OTP]" in message,

            "intent":
                "NON_OTP",

            "sharing_request":
                False,

            "third_party_request":
                False,

            "urgency":
                False,

            "threat":
                False,

            "phishing":
                False,

            "possible_unrequested":
                False,

            "confidence":
                "low",

            "reason":
                "Unable to perform LLM intent analysis.",
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
    expected_otp: bool = False,
    foreground_app: str = "",
    screen_unlocked: bool = True,
) -> Dict[str, Any]:
    """
    Main entry point used by backend/main.py.

    Parameters:

        sender
            SMS sender.

        message
            SANITIZED SMS.

        expected_otp
            Android's context-based indication that an OTP
            may have been expected.

        foreground_app
            Package name of the recently active app.

        screen_unlocked
            Whether the device screen was unlocked.

    Returns:

        Complete OTP analysis + risk verdict.
    """

    # ========================================================
    # 1. SAFETY CHECK
    # ========================================================
    #
    # The OTP agent should receive [OTP], not the real OTP.
    #
    # We cannot reliably prove that the original OTP has
    # been removed, but we can detect the expected placeholder.
    # ========================================================

    has_otp = (
        "[OTP]" in message
    )


    # ========================================================
    # 2. URL PLACEHOLDER
    # ========================================================
    #
    # URL Agent is responsible for actual URL analysis.
    #
    # The OTP Agent only needs to know whether the message
    # contains a URL placeholder.
    # ========================================================

    has_url = (
        "[URL]" in message
    )


    # ========================================================
    # 3. SENDER SIGNAL
    # ========================================================

    plain_mobile_sender = (
        is_plain_mobile_sender(
            sender
        )
    )


    # ========================================================
    # 4. LLM INTENT DETECTION
    # ========================================================

    llm_result = detect_otp_intent(
        message
    )


    # ========================================================
    # 5. RISK ENGINE
    # ========================================================

    risk_result = calculate_risk(

        llm_result=llm_result,

        has_otp=has_otp,

        has_url=has_url,

        plain_mobile_sender=
            plain_mobile_sender,

        foreground_app=
            foreground_app,

        screen_unlocked=
            screen_unlocked,

        expected_otp=
            expected_otp,
    )


    # ========================================================
    # 6. FINAL RESULT
    # ========================================================

    return {

        # ----------------------------------------------------
        # OTP information
        # ----------------------------------------------------

        "otp_detected":
            has_otp,

        # NEVER return the actual OTP.
        "otp_code":
            None,


        # ----------------------------------------------------
        # LLM intent
        # ----------------------------------------------------

        "intent":
            llm_result.get(
                "intent",
                "NON_OTP"
            ),


        "llm_reason":
            llm_result.get(
                "reason",
                ""
            ),


        "llm_confidence":
            llm_result.get(
                "confidence",
                "low"
            ),


        # ----------------------------------------------------
        # Final risk
        # ----------------------------------------------------

        "level":
            risk_result.get(
                "level",
                "SAFE"
            ),

        "score":
            risk_result.get(
                "score",
                0
            ),

        "confidence":
            risk_result.get(
                "confidence",
                0
            ),

        "reasons":
            risk_result.get(
                "reasons",
                []
            ),


        # ----------------------------------------------------
        # Signals
        # ----------------------------------------------------

        "signals": {

            "otp_detected":
                has_otp,

            "otp_code_detected":
                has_otp,

            "possible_unrequested":
                llm_result.get(
                    "possible_unrequested",
                    False
                ),

            "sharing_request":
                llm_result.get(
                    "sharing_request",
                    False
                ),

            "third_party_request":
                llm_result.get(
                    "third_party_request",
                    False
                ),

            "plain_mobile_sender":
                plain_mobile_sender,

            "has_url":
                has_url,

            "urgency":
                llm_result.get(
                    "urgency",
                    False
                ),

            "threat":
                llm_result.get(
                    "threat",
                    False
                ),

            "phishing":
                llm_result.get(
                    "phishing",
                    False
                ),

            "repeated_otp":
                False,

            "expected_otp":
                expected_otp,

            "foreground_app":
                foreground_app,

            "screen_unlocked":
                screen_unlocked,
        },


        # ----------------------------------------------------
        # Privacy
        # ----------------------------------------------------

        "privacy": {

            "otp_sent_to_llm":
                False,

            "otp_stored_by_agent":
                False,

            "otp_returned_by_agent":
                False,

            "sanitized_input":
                True,
        },
    }
