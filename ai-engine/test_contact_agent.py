"""
test_contact_agent.py

Manual smoke test for the Contact Agent, covering:
    - Test 1: saved normal contact
    - Test 2: unknown normal sender
    - Test 3: financial scam
    - Test 4: impersonation
    - Test 5: saved contact with suspicious behavior
    - Test 6: MongoDB sender history (repeat sends from the same sender)

Run from the ai-engine/ directory:
    python test_contact_agent.py

MongoDB is optional for this test - if MONGODB_URI isn't set, the agent
degrades gracefully and total_messages/mongo_available will just show
as unavailable in the printed output.
"""


import os
import sys
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_APP_DIR = PROJECT_ROOT / "backend" / "app"

load_dotenv(BACKEND_APP_DIR / ".env")

sys.path.insert(0, str(PROJECT_ROOT / "backend"))
import os
import sys

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

BACKEND_DIR = os.path.join(
    PROJECT_ROOT,
    "backend"
)

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents.contact_agent import analyze_contact


def run_case(name, sender, message, is_saved_contact, contact_name=None):
    print("\n" + "=" * 70)
    print(f"TEST: {name}")
    print("-" * 70)
    print(f"Sender: {sender}  |  Saved: {is_saved_contact}  |  Name: {contact_name}")
    print(f"Message: {message}")

    result = analyze_contact(
        sender=sender,
        message=message,
        is_saved_contact=is_saved_contact,
        contact_name=contact_name,
    )

    print(f"LEVEL: {result['level']}  |  TRUST SCORE: {result['trust']['score']}  |  VERDICT: {result['trust']['verdict']}")
    print(f"SENDER TYPE: {result['sender']['type']} (confidence={result['sender']['confidence']})")
    print(f"CLASSIFICATION: {result['message_analysis']['classification']} "
          f"(spam={result['message_analysis']['spam_probability']}, "
          f"scam={result['message_analysis']['scam_probability']})")
    print(f"IMPERSONATION: {result['impersonation']}")
    print(f"REPUTATION: {result['sender_reputation']}")
    print("REASONS:")
    for r in result["reasons"]:
        print(f"  • {r}")
    print(f"EXPLANATION: {result['short_explanation']}")

    return result


def main():
    # Test 1 - saved normal contact
    run_case(
        "Saved normal contact",
        sender="+919876500001",
        message="Hey, are we meeting at 6?",
        is_saved_contact=True,
        contact_name="Priya",
    )

    # Test 2 - unknown normal sender
    run_case(
        "Unknown normal sender",
        sender="+919876500002",
        message="Your appointment is confirmed for tomorrow.",
        is_saved_contact=False,
    )

    # Test 3 - financial scam
    run_case(
        "Financial scam",
        sender="+919876500003",
        message="URGENT! Send ₹20,000 to this UPI immediately.",
        is_saved_contact=False,
    )

    # Test 4 - impersonation
    run_case(
        "Impersonation (personal number claiming to be SBI)",
        sender="+919876500004",
        message="SBI: Your account will be blocked. Click immediately.",
        is_saved_contact=False,
    )

    # Test 5 - saved contact with suspicious behavior
    run_case(
        "Saved contact, suspicious message",
        sender="+919876500005",
        message="Send me ₹50,000 urgently. Don't call me.",
        is_saved_contact=True,
        contact_name="Rahul",
    )

    # Test 6 - MongoDB sender history (repeat sends, same sender)
    print("\n" + "=" * 70)
    print("TEST: MongoDB sender history")
    print("-" * 70)

    sender = "+919876500006"
    for i in range(3):
        result = analyze_contact(
            sender=sender,
            message=f"Reminder #{i + 1}: please review the document.",
            is_saved_contact=False,
            timestamp=time.time() + i,
        )
        print(
            f"  Message {i + 1}: total_messages="
            f"{result['sender_reputation']['total_messages']}  "
            f"mongo_available={result['sender_reputation']['mongo_available']}"
        )

    print("\n" + "=" * 70)
    print("DONE")
    print("=" * 70)


if __name__ == "__main__":
    main()