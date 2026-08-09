"""
test_url_agent.py

Manual smoke test for the URL agent. Mirrors the style of test_otp.py:
a list of sample messages run through the agent with the results
printed for eyeballing, not an automated pass/fail test suite.

Run from the ai-engine/ directory:
    python test_url_agent.py

Requires GROQ_API_KEY to be set in the environment first:
    # Windows PowerShell
    $env:GROQ_API_KEY="your-key-here"
    # Mac/Linux
    export GROQ_API_KEY="your-key-here"
"""

import os
import sys

# Allow "from agents.url_agent import analyze_url" to work when this file
# is run directly from the ai-engine/ folder.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents.url_agent import analyze_url


messages = [

    {
        "name": "Legitimate delivery notice",
        "body": (
            "Your package is out for delivery and should arrive today. "
            "Track it here: https://www.fedex.com/track/1234567890"
        ),
    },

    {
        "name": "Phishing - fake bank alert",
        "body": (
            "Alert - Netflix: Payment failed, we will close your account "
            "due to missing payment info. Log in now: "
            "http://netflix-billing-update.example.com/login"
        ),
    },

    {
        "name": "Spam - gambling promo",
        "body": (
            "Congrats! You've won a free spin bonus. Claim your prize "
            "now at https://spin-rewards-xxxx.example/claim"
        ),
    },

    {
        "name": "Legitimate - no URL, personal message",
        "body": "Hey, are we still on for dinner tonight at 7?",
    },

    {
        "name": "Phishing - urgency + credential harvest",
        "body": (
            "USPS: Your package could not be delivered due to an "
            "incomplete address. Update your details within 24 hours "
            "or it will be returned: http://usps-redelivery.example.net"
        ),
    },
]


for test in messages:

    print("\n" + "=" * 70)
    print(f"TEST: {test['name']}")
    print("-" * 70)
    print(f"MESSAGE: {test['body']}")

    try:
        result = analyze_url(test["body"])

    except Exception as e:
        print(f"ERROR: {str(e)}")
        continue

    print(f"CATEGORY: {result.get('category')}")
    print(f"IS_MALICIOUS: {result.get('is_malicious')}")
    print(f"CONFIDENCE: {result.get('confidence')}")
    print(f"BRAND: {result.get('brand_impersonated')}")
    print(f"URL: {result.get('url')}")
    print(f"BRIEF REASON: {result.get('brief_reason')}")
    print("\nSHORT EXPLANATION:")
    print(f"  {result.get('short_explanation')}")

    context = result.get("context", {})
    if context.get("final_url"):
        print("\nCONTEXT:")
        print(f"  Final URL: {context.get('final_url')}")
        print(f"  Domain info: {context.get('domain_info')}")
        print(f"  Brand domain: {context.get('brand_domain')}")

print("\n" + "=" * 70)
print("DONE")
print("=" * 70)