import requests
import json
import csv
from datetime import datetime

API_URL = "http://127.0.0.1:8000/analyze-url"

TEST_CASES = [

    # ============================================================
    # CATEGORY 1: LEGITIMATE URLS
    # ============================================================

    {
        "id": "L01",
        "category": "legitimate",
        "expected": "legitimate",
        "sender": "TEST-GOOGLE",
        "body": "Visit https://www.google.com/ for more information."
    },

    {
        "id": "L02",
        "category": "legitimate",
        "expected": "legitimate",
        "sender": "TEST-MICROSOFT",
        "body": "Visit https://www.microsoft.com/ for more information."
    },

    {
        "id": "L03",
        "category": "legitimate",
        "expected": "legitimate",
        "sender": "TEST-AMAZON",
        "body": "Visit https://www.amazon.in/ for more information."
    },

    {
        "id": "L04",
        "category": "legitimate",
        "expected": "legitimate",
        "sender": "TEST-PAYPAL",
        "body": "Visit https://www.paypal.com/ for more information."
    },

    {
        "id": "L05",
        "category": "legitimate",
        "expected": "legitimate",
        "sender": "TEST-GITHUB",
        "body": "Visit https://github.com/ for more information."
    },

    {
        "id": "L06",
        "category": "legitimate",
        "expected": "legitimate",
        "sender": "TEST-APPLE",
        "body": "Visit https://www.apple.com/ for more information."
    },


    # ============================================================
    # CATEGORY 2: TYPOSQUATTING
    # Safe synthetic .example domains
    # ============================================================

    {
        "id": "T01",
        "category": "typosquatting",
        "expected": "malicious",
        "sender": "TEST-TYPOSQUAT-PAYPAL",
        "body": (
            "Your PayPal account requires verification. "
            "Please visit https://paypa1.example/verify"
        )
    },

    {
        "id": "T02",
        "category": "typosquatting",
        "expected": "malicious",
        "sender": "TEST-TYPOSQUAT-GOOGLE",
        "body": (
            "Your Google account requires verification. "
            "Visit https://g00gle.example/login"
        )
    },

    {
        "id": "T03",
        "category": "typosquatting",
        "expected": "malicious",
        "sender": "TEST-TYPOSQUAT-MICROSOFT",
        "body": (
            "Microsoft security alert. "
            "Verify your account at https://micros0ft.example/security"
        )
    },

    {
        "id": "T04",
        "category": "typosquatting",
        "expected": "malicious",
        "sender": "TEST-TYPOSQUAT-AMAZON",
        "body": (
            "Your Amazon account needs verification. "
            "Visit https://amaz0n.example/verify"
        )
    },

    {
        "id": "T05",
        "category": "typosquatting",
        "expected": "malicious",
        "sender": "TEST-TYPOSQUAT-APPLE",
        "body": (
            "Your Apple ID requires verification. "
            "Visit https://app1e.example/verify"
        )
    },

    {
        "id": "T06",
        "category": "typosquatting",
        "expected": "malicious",
        "sender": "TEST-TYPOSQUAT-GITHUB",
        "body": (
            "GitHub security verification required. "
            "Visit https://githuub.example/login"
        )
    },


    # ============================================================
    # CATEGORY 3: BRAND IMPERSONATION
    # ============================================================

    {
        "id": "B01",
        "category": "brand_impersonation",
        "expected": "malicious",
        "sender": "TEST-BRAND-PAYPAL",
        "body": (
            "PayPal Security: Your account has been restricted. "
            "Verify immediately at https://paypal-security.example/"
        )
    },

    {
        "id": "B02",
        "category": "brand_impersonation",
        "expected": "malicious",
        "sender": "TEST-BRAND-GOOGLE",
        "body": (
            "Google Security Alert: Confirm your account at "
            "https://google-account-verify.example/"
        )
    },

    {
        "id": "B03",
        "category": "brand_impersonation",
        "expected": "malicious",
        "sender": "TEST-BRAND-MICROSOFT",
        "body": (
            "Microsoft Account Alert: "
            "https://microsoft-security.example/verify"
        )
    },


    # ============================================================
    # CATEGORY 4: PHISHING-LIKE MESSAGES
    # ============================================================

    {
        "id": "P01",
        "category": "phishing",
        "expected": "malicious",
        "sender": "TEST-PHISHING-01",
        "body": (
            "URGENT! Your account will be suspended. "
            "Verify your identity immediately at "
            "https://account-verification.example/"
        )
    },

    {
        "id": "P02",
        "category": "phishing",
        "expected": "malicious",
        "sender": "TEST-PHISHING-02",
        "body": (
            "Security alert! Unusual activity detected. "
            "Confirm your account now: "
            "https://secure-login.example/"
        )
    },

    {
        "id": "P03",
        "category": "phishing",
        "expected": "malicious",
        "sender": "TEST-PHISHING-03",
        "body": (
            "Your payment failed. Update your payment information "
            "at https://payment-update.example/"
        )
    },


    # ============================================================
    # CATEGORY 5: URL EXTRACTION
    # ============================================================

    {
        "id": "E01",
        "category": "url_extraction",
        "expected": "legitimate",
        "sender": "TEST-EXTRACTION-01",
        "body": (
            "Hello! Please visit our website for more information: "
            "https://www.google.com/"
        )
    },

    {
        "id": "E02",
        "category": "url_extraction",
        "expected": "malicious",
        "sender": "TEST-EXTRACTION-02",
        "body": (
            "Your account requires verification. "
            "Click here: https://paypa1.example/verify"
        )
    },


    # ============================================================
    # CATEGORY 6: MULTIPLE URLs
    # ============================================================

    {
        "id": "M01",
        "category": "multiple_urls",
        "expected": "malicious",
        "sender": "TEST-MULTIPLE-01",
        "body": (
            "Official website: https://www.google.com/ "
            "Verification: https://google-account-verify.example/"
        )
    },

    {
        "id": "M02",
        "category": "multiple_urls",
        "expected": "legitimate",
        "sender": "TEST-MULTIPLE-02",
        "body": (
            "Useful links: "
            "https://www.microsoft.com/ "
            "https://github.com/"
        )
    },


    # ============================================================
    # CATEGORY 7: FALSE-POSITIVE CONTROLS
    # ============================================================

    {
        "id": "F01",
        "category": "false_positive_control",
        "expected": "legitimate",
        "sender": "TEST-FP-01",
        "body": "Sign in to GitHub at https://github.com/login"
    },

    {
        "id": "F02",
        "category": "false_positive_control",
        "expected": "legitimate",
        "sender": "TEST-FP-02",
        "body": "Manage your Google account at https://accounts.google.com/"
    },

    {
        "id": "F03",
        "category": "false_positive_control",
        "expected": "legitimate",
        "sender": "TEST-FP-03",
        "body": "Visit PayPal securely at https://www.paypal.com/signin"
    },


    # ============================================================
    # CATEGORY 8: NO URL / EDGE CASES
    # ============================================================

    {
        "id": "X01",
        "category": "no_url",
        "expected": "unknown",
        "sender": "TEST-NO-URL",
        "body": "Hello, this message contains no URL."
    },

    {
        "id": "X02",
        "category": "empty_message",
        "expected": "unknown",
        "sender": "TEST-EMPTY",
        "body": ""
    }
]


def build_request(test_case):
    return {
        "sender": test_case["sender"],
        "body": test_case["body"],
        "timestamp": int(datetime.now().timestamp()),
        "source": "blackbox_test",
        "expected_otp": False,
        "foreground_app": "",
        "screen_unlocked": True,
        "is_saved_contact": False,
        "contact_name": None
    }


def classify_result(response, expected):
    """
    Basic black-box verdict.

    We deliberately keep this simple initially.
    We can refine the expected-category mapping after
    seeing your agent's actual output categories.
    """

    if not response:
        return "ERROR"

    actual_category = str(response.get("category", "")).lower()
    is_malicious = response.get("is_malicious")

    if expected == "legitimate":
        if actual_category == "legitimate" and is_malicious is False:
            return "PASS"

    elif expected == "malicious":
        if is_malicious is True:
            return "PASS"

        suspicious_categories = {
            "malicious",
            "phishing",
            "suspicious",
            "scam"
        }

        if actual_category in suspicious_categories:
            return "PASS"

    elif expected == "unknown":
        if actual_category == "unknown":
            return "PASS"

    return "FAIL"


def run_tests():
    results = []

    print("=" * 70)
    print("SCAMSHIELD URL AGENT - BLACK-BOX TEST")
    print("=" * 70)
    print(f"Endpoint: {API_URL}")
    print(f"Total tests: {len(TEST_CASES)}")
    print("=" * 70)

    for test in TEST_CASES:

        print(f"\n[{test['id']}] {test['category']}")
        print(f"Input: {test['body']}")

        request_data = build_request(test)

        try:
            response = requests.post(
                API_URL,
                json=request_data,
                timeout=60
            )

            try:
                response_json = response.json()
            except ValueError:
                response_json = {
                    "raw_response": response.text
                }

            verdict = classify_result(
                response_json,
                test["expected"]
            )

            result = {
                "test_id": test["id"],
                "category": test["category"],
                "expected": test["expected"],
                "status_code": response.status_code,
                "actual_category": response_json.get("category"),
                "is_malicious": response_json.get("is_malicious"),
                "confidence": response_json.get("confidence"),
                "url": response_json.get("url"),
                "brand_impersonated": response_json.get(
                    "brand_impersonated"
                ),
                "verdict": verdict,
                "input": test["body"],
                "response": response_json
            }

            results.append(result)

            print(f"HTTP Status : {response.status_code}")
            print(f"Category    : {response_json.get('category')}")
            print(f"Malicious   : {response_json.get('is_malicious')}")
            print(f"Confidence  : {response_json.get('confidence')}")
            print(f"Verdict     : {verdict}")

        except requests.exceptions.RequestException as e:

            print(f"ERROR: {e}")

            results.append({
                "test_id": test["id"],
                "category": test["category"],
                "expected": test["expected"],
                "status_code": None,
                "actual_category": None,
                "is_malicious": None,
                "confidence": None,
                "url": None,
                "brand_impersonated": None,
                "verdict": "ERROR",
                "input": test["body"],
                "response": {
                    "error": str(e)
                }
            })

    save_results(results)


def save_results(results):

    # ------------------------------------------------------------
    # Save complete JSON results
    # ------------------------------------------------------------

    with open(
        "url_agent_test_results.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            results,
            f,
            indent=4,
            ensure_ascii=False
        )


    # ------------------------------------------------------------
    # Save summary CSV
    # ------------------------------------------------------------

    with open(
        "url_agent_test_results.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=[
                "test_id",
                "category",
                "expected",
                "actual_category",
                "is_malicious",
                "confidence",
                "url",
                "brand_impersonated",
                "status_code",
                "verdict"
            ]
        )

        writer.writeheader()

        for result in results:

            writer.writerow({
                "test_id": result["test_id"],
                "category": result["category"],
                "expected": result["expected"],
                "actual_category": result["actual_category"],
                "is_malicious": result["is_malicious"],
                "confidence": result["confidence"],
                "url": result["url"],
                "brand_impersonated": result["brand_impersonated"],
                "status_code": result["status_code"],
                "verdict": result["verdict"]
            })


    # ------------------------------------------------------------
    # Print summary
    # ------------------------------------------------------------

    total = len(results)

    passed = sum(
        1 for r in results
        if r["verdict"] == "PASS"
    )

    failed = sum(
        1 for r in results
        if r["verdict"] == "FAIL"
    )

    errors = sum(
        1 for r in results
        if r["verdict"] == "ERROR"
    )

    print("\n")
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    print(f"Total tests : {total}")
    print(f"Passed      : {passed}")
    print(f"Failed      : {failed}")
    print(f"Errors      : {errors}")

    if total > 0:
        print(
            f"Pass rate   : {(passed / total) * 100:.2f}%"
        )

    print("=" * 70)
    print("Results saved to:")
    print("  url_agent_test_results.json")
    print("  url_agent_test_results.csv")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()