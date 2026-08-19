import requests
import json
import csv
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

API_URL = "http://127.0.0.1:8000/analyze-sms"

TIMEOUT = 60


# ============================================================
# TEST CASES
# ============================================================

TEST_CASES = [

    # ========================================================
    # O — NORMAL OTP
    # ========================================================

    {
        "id": "O01",
        "category": "NORMAL_OTP",
        "expected_intent": "NORMAL_OTP",
        "expected_level": "SAFE",
        "sender": "BANK-OTP",
        "body": "Your OTP is [OTP].",
        "expected_otp": True,
    },

    {
        "id": "O02",
        "category": "NORMAL_OTP",
        "expected_intent": "NORMAL_OTP",
        "expected_level": "SAFE",
        "sender": "BANK-OTP",
        "body": "Your OTP is [OTP]. Do not share it with anyone.",
        "expected_otp": True,
    },

    {
        "id": "O03",
        "category": "NORMAL_OTP",
        "expected_intent": "NORMAL_OTP",
        "expected_level": "SAFE",
        "sender": "BANK-OTP",
        "body": "Use [OTP] to complete your login.",
        "expected_otp": True,
    },

    {
        "id": "O04",
        "category": "NORMAL_OTP",
        "expected_intent": "NORMAL_OTP",
        "expected_level": "SAFE",
        "sender": "SHOP-OTP",
        "body": "Your verification code is [OTP]. Valid for 10 minutes.",
        "expected_otp": True,
    },


    # ========================================================
    # S — OTP SHARING REQUEST
    # ========================================================

    {
        "id": "S01",
        "category": "OTP_SHARING_REQUEST",
        "expected_intent": "OTP_SHARING_REQUEST",
        "expected_level": "CAUTION",
        "sender": "BANK-OTP",
        "body": "Your OTP is [OTP]. Please send the OTP to verify your account.",
        "expected_otp": True,
    },

    {
        "id": "S02",
        "category": "OTP_SHARING_REQUEST",
        "expected_intent": "OTP_SHARING_REQUEST",
        "expected_level": "CAUTION",
        "sender": "SERVICE",
        "body": "Give me the OTP [OTP] to complete verification.",
        "expected_otp": True,
    },

    {
        "id": "S03",
        "category": "OTP_SHARING_REQUEST",
        "expected_intent": "OTP_SHARING_REQUEST",
        "expected_level": "CAUTION",
        "sender": "SECURITY",
        "body": "Please provide the OTP [OTP] to confirm your identity.",
        "expected_otp": True,
    },


    # ========================================================
    # T — OTP THREAT
    # ========================================================

    {
        "id": "T01",
        "category": "OTP_THREAT",
        "expected_intent": "OTP_THREAT",
        "expected_level": "CAUTION",
        "sender": "SECURITY",
        "body": "Your account will be blocked. Give me the OTP [OTP] immediately.",
        "expected_otp": True,
    },

    {
        "id": "T02",
        "category": "OTP_THREAT",
        "expected_intent": "OTP_THREAT",
        "expected_level": "CAUTION",
        "sender": "BANK",
        "body": "URGENT! Your account will be suspended unless you provide OTP [OTP].",
        "expected_otp": True,
    },

    {
        "id": "T03",
        "category": "OTP_THREAT",
        "expected_intent": "OTP_THREAT",
        "expected_level": "CAUTION",
        "sender": "SECURITY",
        "body": "Failure to provide OTP [OTP] immediately will result in account closure.",
        "expected_otp": True,
    },


    # ========================================================
    # P — OTP PHISHING
    # ========================================================

    {
        "id": "P01",
        "category": "OTP_PHISHING",
        "expected_intent": "OTP_PHISHING",
        "expected_level": "CAUTION",
        "sender": "SECURITY",
        "body": "Your account was compromised. Enter OTP [OTP] to secure it.",
        "expected_otp": True,
    },

    {
        "id": "P02",
        "category": "OTP_PHISHING",
        "expected_intent": "OTP_PHISHING",
        "expected_level": "CAUTION",
        "sender": "VERIFY",
        "body": "Security verification required. Confirm your account using OTP [OTP].",
        "expected_otp": True,
    },

    {
        "id": "P03",
        "category": "OTP_PHISHING",
        "expected_intent": "OTP_PHISHING",
        "expected_level": "CAUTION",
        "sender": "LOGIN",
        "body": "Unusual login detected. Use OTP [OTP] to prevent unauthorized access.",
        "expected_otp": True,
    },


    # ========================================================
    # C — CUSTOMER CARE SCAM
    # ========================================================

    {
        "id": "C01",
        "category": "OTP_CUSTOMER_CARE_SCAM",
        "expected_intent": "OTP_CUSTOMER_CARE_SCAM",
        "expected_level": "DANGER",
        "sender": "CUSTOMERCARE",
        "body": "Call customer care and provide the OTP [OTP] to verify your account.",
        "expected_otp": True,
    },

    {
        "id": "C02",
        "category": "OTP_CUSTOMER_CARE_SCAM",
        "expected_intent": "OTP_CUSTOMER_CARE_SCAM",
        "expected_level": "DANGER",
        "sender": "SUPPORT",
        "body": "Customer support needs OTP [OTP] to process your refund.",
        "expected_otp": True,
    },

    {
        "id": "C03",
        "category": "OTP_CUSTOMER_CARE_SCAM",
        "expected_intent": "OTP_CUSTOMER_CARE_SCAM",
        "expected_level": "DANGER",
        "sender": "SERVICE",
        "body": "Our representative will call you. Give them OTP [OTP] for verification.",
        "expected_otp": True,
    },


    # ========================================================
    # U — UNREQUESTED OTP
    # ========================================================

    {
        "id": "U01",
        "category": "UNREQUESTED_OTP",
        "expected_intent": "UNREQUESTED_OTP",
        "expected_level": "CAUTION",
        "sender": "BANK",
        "body": "Your OTP is [OTP].",
        "expected_otp": False,
    },

    {
        "id": "U02",
        "category": "UNREQUESTED_OTP",
        "expected_intent": "UNREQUESTED_OTP",
        "expected_level": "CAUTION",
        "sender": "LOGIN",
        "body": "A verification code [OTP] was generated for your account.",
        "expected_otp": False,
    },


    # ========================================================
    # N — NON OTP
    # ========================================================

    {
        "id": "N01",
        "category": "NON_OTP",
        "expected_intent": "NON_OTP",
        "expected_level": "NOT_OTP",
        "sender": "BANK",
        "body": "Your account statement is ready.",
        "expected_otp": False,
    },

    {
        "id": "N02",
        "category": "NON_OTP",
        "expected_intent": "NON_OTP",
        "expected_level": "NOT_OTP",
        "sender": "FRIEND",
        "body": "Hey, are you coming tomorrow?",
        "expected_otp": False,
    },

    {
        "id": "N03",
        "category": "NON_OTP",
        "expected_intent": "NON_OTP",
        "expected_level": "NOT_OTP",
        "sender": "SERVICE",
        "body": "Your order has been shipped.",
        "expected_otp": False,
    },


    # ========================================================
    # X — PRIVACY / SANITIZATION
    # ========================================================

    {
        "id": "X01",
        "category": "PRIVACY_SANITIZATION",
        "expected_intent": "NORMAL_OTP",
        "expected_level": "SAFE",
        "sender": "BANK",
        "body": "Your OTP is [OTP]. Do not share it.",
        "expected_otp": True,
    },

    {
        "id": "X02",
        "category": "PRIVACY_SANITIZATION",
        "expected_intent": "OTP_SHARING_REQUEST",
        "expected_level": "CAUTION",
        "sender": "BANK",
        "body": "Your OTP is [OTP]. Send it to customer support.",
        "expected_otp": True,
    },


    # ========================================================
    # URL CONTEXT
    # ========================================================

    {
        "id": "URL01",
        "category": "OTP_WITH_URL",
        "expected_intent": "OTP_PHISHING",
        "expected_level": "CAUTION",
        "sender": "SECURITY",
        "body": "Verify your account using OTP [OTP] at [URL].",
        "expected_otp": True,
    },


    # ========================================================
    # MOBILE SENDER CONTEXT
    # ========================================================

    {
        "id": "CTX01",
        "category": "MOBILE_SENDER",
        "expected_intent": "OTP_SHARING_REQUEST",
        "expected_level": "CAUTION",
        "sender": "+919876543210",
        "body": "Send me the OTP [OTP] for verification.",
        "expected_otp": True,
    },

    {
        "id": "CTX02",
        "category": "MOBILE_SENDER",
        "expected_intent": "NORMAL_OTP",
        "expected_level": "SAFE",
        "sender": "+919876543210",
        "body": "Your OTP is [OTP]. Do not share it with anyone.",
        "expected_otp": True,
    },


    # ========================================================
    # SCREEN LOCK CONTEXT
    # ========================================================

    {
        "id": "CTX03",
        "category": "LOCKED_SCREEN",
        "expected_intent": "NORMAL_OTP",
        "expected_level": "SAFE",
        "sender": "BANK",
        "body": "Your OTP is [OTP].",
        "expected_otp": True,
        "screen_unlocked": False,
    },


    # ========================================================
    # MIXED / HARD CASES
    # ========================================================

    {
        "id": "H01",
        "category": "HARD_CASE",
        "expected_intent": "OTP_THREAT",
        "expected_level": "DANGER",
        "sender": "+919876543210",
        "body": (
            "URGENT! Your bank account will be permanently blocked. "
            "Give the OTP [OTP] to our representative immediately."
        ),
        "expected_otp": True,
    },

    {
        "id": "H02",
        "category": "HARD_CASE",
        "expected_intent": "OTP_CUSTOMER_CARE_SCAM",
        "expected_level": "DANGER",
        "sender": "+919876543210",
        "body": (
            "Customer care here. Your refund is pending. "
            "Please provide OTP [OTP] to process it."
        ),
        "expected_otp": True,
    },

    {
        "id": "H03",
        "category": "HARD_CASE",
        "expected_intent": "NORMAL_OTP",
        "expected_level": "SAFE",
        "sender": "BANK-OTP",
        "body": (
            "Your login OTP is [OTP]. "
            "Never share this code with anyone."
        ),
        "expected_otp": True,
    },
]


# ============================================================
# REQUEST BUILDER
# ============================================================

def build_request(test):

    return {
        "sender": test["sender"],
        "body": test["body"],
        "timestamp": int(datetime.now().timestamp()),
        "source": "otp_blackbox_test",
        "expected_otp": test.get("expected_otp", False),
        "foreground_app": test.get("foreground_app", ""),
        "screen_unlocked": test.get("screen_unlocked", True),
        "is_saved_contact": False,
        "contact_name": None,
    }


# ============================================================
# BLACK-BOX VERDICT
# ============================================================

def evaluate_result(test, response):

    if not isinstance(response, dict):
        return "FAIL"

    actual_intent = response.get("intent")
    actual_level = response.get("level")

    expected_intent = test.get("expected_intent")
    expected_level = test.get("expected_level")

    intent_match = (
        actual_intent == expected_intent
    )

    level_match = (
        actual_level == expected_level
    )

    # For NOT_OTP, intent + level should both match.
    if expected_intent == "NON_OTP":
        return (
            "PASS"
            if intent_match and level_match
            else "FAIL"
        )

    # For all OTP tests, require both.
    return (
        "PASS"
        if intent_match and level_match
        else "FAIL"
    )


# ============================================================
# RUN TESTS
# ============================================================

def run_tests():

    results = []

    print("=" * 80)
    print("SCAMSHIELD OTP AGENT - BLACK BOX TEST")
    print("=" * 80)

    print(f"Endpoint : {API_URL}")
    print(f"Tests    : {len(TEST_CASES)}")

    print("=" * 80)

    for test in TEST_CASES:

        print()
        print("-" * 80)

        print(
            f"[{test['id']}] "
            f"{test['category']}"
        )

        print(
            f"Expected intent : "
            f"{test['expected_intent']}"
        )

        print(
            f"Expected level  : "
            f"{test['expected_level']}"
        )

        print(
            f"Message         : "
            f"{test['body']}"
        )

        request_data = build_request(test)

        try:

            response = requests.post(
                API_URL,
                json=request_data,
                timeout=TIMEOUT
            )

            try:
                data = response.json()

            except ValueError:

                data = {
                    "raw_response": response.text
                }

            verdict = evaluate_result(
                test,
                data
            )

            result = {

                "test_id":
                    test["id"],

                "category":
                    test["category"],

                "expected_intent":
                    test["expected_intent"],

                "expected_level":
                    test["expected_level"],

                "actual_intent":
                    data.get("intent"),

                "actual_level":
                    data.get("level"),

                "score":
                    data.get("score"),

                "confidence":
                    data.get("confidence"),

                "otp_detected":
                    data.get("otp_detected"),

                "otp_code":
                    data.get("otp_code"),

                "reasons":
                    data.get("reasons", []),

                "signals":
                    data.get("signals", {}),

                "privacy":
                    data.get("privacy", {}),

                "http_status":
                    response.status_code,

                "verdict":
                    verdict,

                "input":
                    test["body"],

                "response":
                    data,
            }

            results.append(result)

            print(
                f"Actual intent   : "
                f"{data.get('intent')}"
            )

            print(
                f"Actual level    : "
                f"{data.get('level')}"
            )

            print(
                f"Risk score      : "
                f"{data.get('score')}"
            )

            print(
                f"Confidence      : "
                f"{data.get('confidence')}"
            )

            print(
                f"OTP detected    : "
                f"{data.get('otp_detected')}"
            )

            print(
                f"OTP code       : "
                f"{data.get('otp_code')}"
            )

            print(
                f"Verdict         : "
                f"{verdict}"
            )

        except requests.exceptions.RequestException as e:

            print(
                f"ERROR: {str(e)}"
            )

            results.append({

                "test_id":
                    test["id"],

                "category":
                    test["category"],

                "expected_intent":
                    test["expected_intent"],

                "expected_level":
                    test["expected_level"],

                "actual_intent":
                    None,

                "actual_level":
                    None,

                "score":
                    None,

                "confidence":
                    None,

                "otp_detected":
                    None,

                "otp_code":
                    None,

                "reasons":
                    [],

                "signals":
                    {},

                "privacy":
                    {},

                "http_status":
                    None,

                "verdict":
                    "ERROR",

                "input":
                    test["body"],

                "response":
                    {
                        "error":
                            str(e)
                    },
            })


    save_results(results)


# ============================================================
# SAVE RESULTS
# ============================================================

def save_results(results):

    # --------------------------------------------------------
    # COMPLETE JSON
    # --------------------------------------------------------

    with open(
        "otp_agent_blackbox_results.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            results,
            f,
            indent=4,
            ensure_ascii=False
        )


    # --------------------------------------------------------
    # CSV SUMMARY
    # --------------------------------------------------------

    with open(
        "otp_agent_blackbox_results.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=[
                "test_id",
                "category",
                "expected_intent",
                "actual_intent",
                "expected_level",
                "actual_level",
                "score",
                "confidence",
                "otp_detected",
                "otp_code",
                "http_status",
                "verdict",
            ]
        )

        writer.writeheader()

        for result in results:

            writer.writerow({

                "test_id":
                    result["test_id"],

                "category":
                    result["category"],

                "expected_intent":
                    result["expected_intent"],

                "actual_intent":
                    result["actual_intent"],

                "expected_level":
                    result["expected_level"],

                "actual_level":
                    result["actual_level"],

                "score":
                    result["score"],

                "confidence":
                    result["confidence"],

                "otp_detected":
                    result["otp_detected"],

                "otp_code":
                    result["otp_code"],

                "http_status":
                    result["http_status"],

                "verdict":
                    result["verdict"],
            })


    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    total = len(results)

    passed = sum(
        1
        for r in results
        if r["verdict"] == "PASS"
    )

    failed = sum(
        1
        for r in results
        if r["verdict"] == "FAIL"
    )

    errors = sum(
        1
        for r in results
        if r["verdict"] == "ERROR"
    )

    print()
    print()
    print("=" * 80)
    print("OTP AGENT BLACK-BOX TEST SUMMARY")
    print("=" * 80)

    print(f"Total tests : {total}")
    print(f"Passed      : {passed}")
    print(f"Failed      : {failed}")
    print(f"Errors      : {errors}")

    if total:

        print(
            f"Pass rate   : "
            f"{passed / total * 100:.2f}%"
        )

    print()
    print("Files generated:")
    print("  otp_agent_blackbox_results.json")
    print("  otp_agent_blackbox_results.csv")

    print("=" * 80)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    run_tests()