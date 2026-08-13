"""
risk_engine.py

Combines:

1. LLM intent detection
2. Local OTP detection
3. Sender information
4. Android foreground-app context
5. Screen state
6. Expected OTP context

The LLM determines WHAT the SMS is trying to do.
The risk engine determines HOW dangerous it is.
"""


def calculate_risk(
    llm_result: dict,
    has_otp: bool,
    has_url: bool,
    plain_mobile_sender: bool,
    foreground_app: str,
    screen_unlocked: bool,
    expected_otp: bool,
) -> dict:

    # =========================================================
    # 1. NOT AN OTP
    # =========================================================

    if not has_otp:

        return {
            "level": "NOT_OTP",
            "score": 0,
            "confidence": 0,
            "reasons": [],
        }


    score = 0
    reasons = []


    # =========================================================
    # 2. GET LLM INTENT
    # =========================================================

    intent = llm_result.get(
        "intent",
        "NON_OTP"
    )

    sharing_request = llm_result.get(
        "sharing_request",
        False
    )

    third_party_request = llm_result.get(
        "third_party_request",
        False
    )

    urgency = llm_result.get(
        "urgency",
        False
    )

    threat = llm_result.get(
        "threat",
        False
    )

    phishing = llm_result.get(
        "phishing",
        False
    )

    possible_unrequested = llm_result.get(
        "possible_unrequested",
        False
    )


    # =========================================================
    # 3. INTENT-BASED RISK
    # =========================================================
    #
    # The LLM decides the intent.
    #
    # We do NOT search for words such as:
    #
    # "give"
    # "share"
    # "urgent"
    #
    # here.
    #
    # The LLM has already interpreted the meaning.
    # =========================================================

    if intent == "OTP_SHARING_REQUEST":

        score += 5

        reasons.append(
            "Message asks you to share or provide the OTP"
        )


    elif intent == "OTP_CUSTOMER_CARE_SCAM":

        score += 6

        reasons.append(
            "Message appears to involve a customer-care or support impersonation"
        )


    elif intent == "OTP_PHISHING":

        score += 6

        reasons.append(
            "Message appears to use phishing techniques"
        )


    elif intent == "OTP_THREAT":

        score += 5

        reasons.append(
            "Message contains threatening or account-blocking language"
        )


    elif intent == "UNREQUESTED_OTP":

        score += 4

        reasons.append(
            "OTP may not have been requested by you"
        )


    elif intent == "NORMAL_OTP":

        # No danger points from intent itself.
        pass


    # =========================================================
    # 4. LLM SIGNALS
    # =========================================================

    if third_party_request:

        score += 3

        reasons.append(
            "Message refers to a third-party representative or agent"
        )


    if urgency:

        score += 2

        reasons.append(
            "Message uses urgency or pressure"
        )


    if threat and intent != "OTP_THREAT":

        score += 3

        reasons.append(
            "Message contains threatening language"
        )


    if phishing and intent != "OTP_PHISHING":

        score += 3

        reasons.append(
            "Message contains phishing indicators"
        )


    if possible_unrequested and intent != "UNREQUESTED_OTP":

        score += 3

        reasons.append(
            "OTP may not have been requested by you"
        )


    # =========================================================
    # 5. URL SIGNAL
    # =========================================================
    #
    # URL Agent still performs its own analysis.
    #
    # Here we only use the fact that a URL exists.
    # =========================================================

    if has_url:

        score += 3

        reasons.append(
            "OTP message contains a link"
        )


    # =========================================================
    # 6. SENDER CONTEXT
    # =========================================================

    if plain_mobile_sender:

        score += 2

        reasons.append(
            "OTP came from a plain mobile number"
        )


    # =========================================================
    # 7. ANDROID CONTEXT
    # =========================================================

    if not expected_otp:

        score += 2

        reasons.append(
            "There is no clear indication that the OTP was expected"
        )


    # =========================================================
    # SCREEN STATE
    # =========================================================

    if not screen_unlocked:

        score += 1

        reasons.append(
            "SMS arrived while the screen was locked"
        )


    # =========================================================
    # 8. FINAL RISK LEVEL
    # =========================================================

    if score >= 8:

        level = "DANGER"

    elif score >= 4:

        level = "CAUTION"

    else:

        level = "SAFE"


    # =========================================================
    # 9. CONFIDENCE
    # =========================================================

    llm_confidence = llm_result.get(
        "confidence",
        "low"
    )

    if isinstance(
        llm_confidence,
        str
    ):

        confidence_map = {

            "low": 40,

            "medium": 70,

            "high": 90,
        }

        llm_confidence_score = (
            confidence_map.get(
                llm_confidence.lower(),
                40
            )
        )

    else:

        # If model returns 0.0 - 1.0
        if llm_confidence <= 1:

            llm_confidence_score = int(
                llm_confidence * 100
            )

        else:

            llm_confidence_score = int(
                llm_confidence
            )


    # Score-based confidence

    score_confidence = min(
        score * 10,
        100
    )


    # Combine both

    confidence = max(
        llm_confidence_score,
        score_confidence
    )


    # =========================================================
    # 10. RETURN
    # =========================================================

    return {

        "level":
            level,

        "score":
            score,

        "confidence":
            confidence,

        "reasons":
            reasons,

    }
