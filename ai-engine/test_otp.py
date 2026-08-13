"""
test_otp.py

Terminal test for the OTP Agent.

Project structure:

Scam_New/
│
├── backend/
│   └── .env
│
└── ai-engine/
    ├── test_otp.py
    ├── risk_engine.py
    │
    ├── agents/
    │   ├── __init__.py
    │   └── otp_agent.py
    │
    ├── prompts/
    │   └── otp_prompts.py
    │
    └── utils/
        └── groq_client.py


Run from:

    cd C:\\Users\\naush\\Desktop\\Scam_New\\ai-engine

Then:

    python test_otp.py

IMPORTANT:
The actual OTP is NOT sent to the LLM.
All test messages use [OTP].
"""

import os
from pathlib import Path

from dotenv import load_dotenv


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

# Current file:
#
# Scam_New/
#     ai-engine/
#         test_otp.py
#
# parent.parent = Scam_New/

PROJECT_ROOT = Path(__file__).resolve().parent.parent

ENV_FILE = PROJECT_ROOT / "backend" / "app" /".env"

load_dotenv(ENV_FILE)


# ============================================================
# CHECK GROQ API KEY
# ============================================================

if not os.getenv("GROQ_API_KEY"):

    raise RuntimeError(
        f"GROQ_API_KEY not found.\n"
        f"Expected .env file at:\n"
        f"{ENV_FILE}"
    )


print("=" * 70)
print("OTP AGENT TEST")
print("=" * 70)

print()
print("Environment loaded from:")
print(ENV_FILE)

print()
print("Groq API key detected: YES")


# ============================================================
# IMPORT OTP AGENT
# ============================================================

try:

    from agents.otp_agent import analyze_otp

except Exception as e:

    print()
    print("=" * 70)
    print("OTP AGENT IMPORT FAILED")
    print("=" * 70)

    print(
        f"\n{type(e).__name__}: {e}"
    )

    raise


# ============================================================
# TEST CASES
# ============================================================

TEST_CASES = [

    {
        "name": "NORMAL OTP",

        "sender": "HDFCBK",

        "message":
            "Your OTP is [OTP]. "
            "Do not share this OTP with anyone.",

        "expected_otp": True,

        "foreground_app":
            "com.hdfcbank.android",

        "screen_unlocked": True,
    },


    {
        "name": "OTP SHARING REQUEST",

        "sender": "HDFCBK",

        "message":
            "Your OTP is [OTP]. "
            "Please share the OTP with our bank representative "
            "to complete your verification.",

        "expected_otp": True,

        "foreground_app":
            "com.hdfcbank.android",

        "screen_unlocked": True,
    },


    {
        "name": "CUSTOMER CARE OTP SCAM",

        "sender": "+919876543210",

        "message":
            "Your OTP is [OTP]. "
            "This is a bank customer care representative. "
            "Give me the OTP immediately to cancel the transaction.",

        "expected_otp": True,

        "foreground_app":
            "com.naush12.mobile",

        "screen_unlocked": True,
    },


    {
        "name": "OTP THREAT",

        "sender": "BANKXX",

        "message":
            "Your OTP is [OTP]. "
            "Share the OTP now or your bank account will be blocked.",

        "expected_otp": False,

        "foreground_app":
            "com.naush12.mobile",

        "screen_unlocked": True,
    },


    {
        "name": "UNREQUESTED OTP",

        "sender": "BANKXX",

        "message":
            "Your verification code is [OTP]. "
            "If you did not request this code, do not share it.",

        "expected_otp": False,

        "foreground_app":
            "com.naush12.mobile",

        "screen_unlocked": True,
    },


    {
        "name": "OTP PHISHING",

        "sender": "BANKXX",

        "message":
            "Your OTP is [OTP]. "
            "Click the link to verify your account and enter the OTP.",

        "expected_otp": False,

        "foreground_app":
            "com.naush12.mobile",

        "screen_unlocked": True,
    },


    {
        "name": "NORMAL ORDER NUMBER - SHOULD NOT BE OTP",

        "sender": "SHOP",

        "message":
            "Your order number is 123456. "
            "Your package will be delivered tomorrow.",

        "expected_otp": False,

        "foreground_app":
            "com.naush12.mobile",

        "screen_unlocked": True,
    },

    {
        "name": "OTP SHARING REQUEST",

        "sender": "HDFCBK",

        "message": (
            "Account Protection Notice\n"
            "A new device attempted to access your account. Your verification OTP is 741926.\n"
            "If this wasn't you, confirm your identity immediately: https://example.com/account-check\n"
            "⏳ OTP valid for 10 minutes. Never share this code with anyone."
        ),

        "expected_otp": True,

        "foreground_app": "com.hdfcbank.android",

        "screen_unlocked": True,
    },

]


# ============================================================
# RUN ONE TEST
# ============================================================

def run_test(test_case: dict):

    print()
    print()
    print("=" * 70)

    print(
        f"TEST: {test_case['name']}"
    )

    print("=" * 70)

    print(
        "\nSender:",
        test_case["sender"]
    )

    print(
        "\nMessage:",
        test_case["message"]
    )

    print(
        "\nExpected OTP:",
        test_case["expected_otp"]
    )

    print(
        "\nForeground App:",
        test_case["foreground_app"]
    )

    print(
        "\nScreen Unlocked:",
        test_case["screen_unlocked"]
    )

    print()
    print("-" * 70)
    print("Calling OTP Agent...")
    print("-" * 70)


    # ========================================================
    # CALL OTP AGENT
    # ========================================================

    try:

        result = analyze_otp(

            sender=test_case["sender"],

            message=test_case["message"],

            expected_otp=
                test_case["expected_otp"],

            foreground_app=
                test_case["foreground_app"],

            screen_unlocked=
                test_case["screen_unlocked"],
        )


    except Exception as e:

        print()
        print("❌ TEST FAILED")

        print(
            f"{type(e).__name__}: {e}"
        )

        return False


    # ========================================================
    # PRINT COMPLETE RESULT
    # ========================================================

    print()
    print("=" * 70)
    print("OTP AGENT RESULT")
    print("=" * 70)


    # --------------------------------------------------------
    # Main result
    # --------------------------------------------------------

    # --------------------------------------------------------
    # LLM signals
    # --------------------------------------------------------

    print()
    print("-" * 70)
    print("LLM SIGNALS")
    print("-" * 70)

    signals = result.get(
        "signals",
        {}
    )

    llm_signals = [
        "sharing_request",
        "third_party_request",
        "urgency",
        "threat",
        "phishing",
        "possible_unrequested",
    ]

    for signal in llm_signals:

        print(
            f"{signal}:",
            signals.get(
                signal,
                "N/A"
            )
        )

    # --------------------------------------------------------
    # Reasons
    # --------------------------------------------------------

    print()
    print("-" * 70)
    print("RISK REASONS")
    print("-" * 70)

    reasons = result.get(
        "reasons",
        []
    )

    if reasons:

        for reason in reasons:

            print(
                f"  • {reason}"
            )

    else:

        print(
            "  No reasons returned."
        )


    # --------------------------------------------------------
    # Signals
    # --------------------------------------------------------

    signals = result.get(
        "signals",
        {}
    )

    if signals:

        print()
        print("-" * 70)
        print("RISK ENGINE SIGNALS")
        print("-" * 70)

        for key, value in signals.items():

            print(
                f"{key}: {value}"
            )


    # --------------------------------------------------------
    # Privacy information
    # --------------------------------------------------------

    privacy = result.get(
        "privacy",
        {}
    )

    if privacy:

        print()
        print("-" * 70)
        print("PRIVACY")
        print("-" * 70)

        for key, value in privacy.items():

            print(
                f"{key}: {value}"
            )


    # ========================================================
    # CHECK PRIVACY
    # ========================================================

    print()
    print("-" * 70)
    print("PRIVACY CHECK")
    print("-" * 70)

    message = test_case["message"]

    if "[OTP]" in message:

        print(
            "✅ Test message contains [OTP]"
        )

    else:

        print(
            "⚠️ Test message does not contain [OTP]"
        )


    print()
    print("✅ TEST COMPLETED")

    return True


# ============================================================
# MAIN
# ============================================================

def main():

    successful = 0
    failed = 0


    print()
    print(
        "The actual OTP is never included in these tests."
    )

    print(
        "The LLM receives [OTP] instead."
    )


    # ========================================================
    # RUN ALL TEST CASES
    # ========================================================

    for test_case in TEST_CASES:

        success = run_test(
            test_case
        )

        if success:

            successful += 1

        else:

            failed += 1


    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print()
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    print(
        f"\nSuccessful: {successful}"
    )

    print(
        f"Failed:     {failed}"
    )

    print(
        f"Total:      {len(TEST_CASES)}"
    )

    print()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()