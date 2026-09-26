"""
evaluate_precision_recall.py

Precision/recall evaluation of the FULL pipeline (POST /analyze-sms ->
LangGraph coordinator's final risk_score/status), against a labeled set
of messages.

WHY THE FULL PIPELINE, NOT ONE AGENT:
The individual agent blackbox tests (test_contact_agent_blackbox.py,
url_agent_blackbox_test.py, otp_agent_blackbox_test.py) already check
each agent's own behavior against expected intents/categories. This
script instead measures what a user actually experiences: given a real
SMS, does the SYSTEM'S final verdict correctly say "risky" for scams and
"safe" for legitimate messages.

DEFINING "POSITIVE":
Ground truth: each test message is hand-labeled is_scam=True/False.
Prediction: the coordinator returns a 0-100 risk_score and a status
(SAFE/LOW/MEDIUM/HIGH/CRITICAL). "Positive" (predicted scam) is
risk_score >= THRESHOLD. Rather than hardcode what counts as "risky
enough", this script:
    1. Reports precision/recall/F1 at your CURRENT_THRESHOLD (edit
       below to match your product's real alert cutoff).
    2. Sweeps every threshold 0-100 and reports the one that maximizes
       F1, so you can see whether your current cutoff is well-chosen.
    3. Saves every message's true label, score, and prediction to CSV,
       and flags every misclassification.

WHERE TO PUT IT:   backend/scripts/evaluate_precision_recall.py
                    (same folder as your other blackbox test scripts,
                    which this borrows request/response style from)
HOW TO RUN:        1. start the backend: uvicorn app.main:app --reload
                    2. python scripts/evaluate_precision_recall.py
                       (or: python scripts/evaluate_precision_recall.py --base-url http://host:port)

Edit TEST_CASES below to add real messages from your own logs once you
have some - the built-in set is a representative starting point mixing
OTP scams, URL phishing, contact-based scams, spam, and legitimate
messages of several kinds.
"""

import argparse
import csv
import os
import random
import string
import sys
import time
from pathlib import Path

import requests

DEFAULT_BASE_URL = os.environ.get("SCAMSHIELD_BASE_URL", "http://127.0.0.1:8000")
ANALYZE_URL_PATH = "/analyze-sms"
REQUEST_TIMEOUT = 60
CURRENT_THRESHOLD = 35  # edit to match whatever score your app treats as "flag this"

HERE = Path(__file__).resolve().parent
OUT_CSV = HERE / "precision_recall_results.csv"


def _random_indian_mobile():
    first = random.choice("6789")
    rest = "".join(random.choices(string.digits, k=9))
    return "+91" + first + rest


# ============================================================================
# LABELED TEST SET
# is_scam: ground truth. True = this message IS a scam/malicious/risky
# message a user should be warned about. False = legitimate/benign.
# ============================================================================

TEST_CASES = [
    # ---- OTP-based scams (is_scam = True) ----
    {"category": "otp_sharing_request", "is_scam": True, "sender": "+919876543210",
     "body": "Your OTP is 482913. Please share it with our bank representative to complete verification.",
     "is_saved_contact": False},
    {"category": "otp_threat", "is_scam": True, "sender": "+919876543211",
     "body": "URGENT! Your account will be permanently blocked. Give the OTP 592014 to our representative immediately.",
     "is_saved_contact": False},
    {"category": "otp_customer_care_scam", "is_scam": True, "sender": "+919876543212",
     "body": "Customer care here regarding your refund. Please provide OTP 738291 to process it.",
     "is_saved_contact": False},

    # ---- Legit OTP (is_scam = False) ----
    {"category": "normal_otp", "is_scam": False, "sender": "HDFCBK",
     "body": "Your OTP is 482913. Valid for 10 minutes. Do not share this OTP with anyone.",
     "is_saved_contact": False},
    {"category": "normal_otp", "is_scam": False, "sender": "AMAZON",
     "body": "Your Amazon verification code is 118273. Never share this code with anyone.",
     "is_saved_contact": False},

    # ---- URL phishing (is_scam = True) ----
    {"category": "phishing_bank", "is_scam": True, "sender": "+919876543213",
     "body": "Alert - HDFC Bank: Your account will be suspended due to KYC issue. Verify now: http://hdfc-kyc-verify.example/login",
     "is_saved_contact": False},
    {"category": "phishing_delivery", "is_scam": True, "sender": "+919876543214",
     "body": "Your parcel is held at customs. Pay the pending fee to release delivery: http://customs-fee-pay.example/",
     "is_saved_contact": False},
    {"category": "phishing_prize", "is_scam": True, "sender": "+919876543215",
     "body": "Congratulations! You've won a lucky draw prize of Rs 5,00,000. Claim now: http://bit.ly/luckyclaim99",
     "is_saved_contact": False},

    # ---- Legit URLs / messages (is_scam = False) ----
    {"category": "legit_delivery", "is_scam": False, "sender": "AMZN",
     "body": "Your package is out for delivery and should arrive today. Track it: https://www.amazon.in/track/1234567890",
     "is_saved_contact": False},
    {"category": "legit_appointment", "is_scam": False, "sender": "+919876500002",
     "body": "Your appointment is confirmed for tomorrow at 10am.",
     "is_saved_contact": False},

    # ---- Contact-based scams (is_scam = True) ----
    {"category": "impersonation_bank", "is_scam": True, "sender": "+919876543216",
     "body": "SBI: Your account will be blocked. Send your card number and CVV immediately to avoid penalty.",
     "is_saved_contact": False},
    {"category": "financial_scam", "is_scam": True, "sender": "+919876543217",
     "body": "URGENT! Send Rs 20,000 to this UPI ID immediately or face legal action.",
     "is_saved_contact": False},
    {"category": "prize_scam_secrecy", "is_scam": True, "sender": "+919876543218",
     "body": "You have won a prize. Don't tell anyone about this, just transfer the small processing fee now.",
     "is_saved_contact": False},
    {"category": "emergency_money_scam", "is_scam": True, "sender": "+919876543219",
     "body": "I've had an accident, send 20000 rupees urgently, don't call me right now.",
     "is_saved_contact": True, "contact_name": "Rahul"},

    # ---- Legit personal / saved-contact messages (is_scam = False) ----
    {"category": "legit_saved_contact", "is_scam": False, "sender": "+919876500001",
     "body": "Hey, are we still meeting at 6?",
     "is_saved_contact": True, "contact_name": "Priya"},
    {"category": "legit_reminder", "is_scam": False, "sender": "+919876500003",
     "body": "Reminder: your electricity bill of Rs 1,240 is due on the 5th.",
     "is_saved_contact": False},
    {"category": "legit_casual", "is_scam": False, "sender": "+919876500004",
     "body": "Good morning! Hope you have a great day.",
     "is_saved_contact": True, "contact_name": "Mom"},

    # ---- Spam, not necessarily a targeted scam, but still risky (is_scam = True) ----
    {"category": "spam_loan", "is_scam": True, "sender": "+919876543220",
     "body": "Get instant personal loan up to 5 lakhs with zero documentation! Apply now: http://bit.ly/instaloan",
     "is_saved_contact": False},
    {"category": "spam_lottery", "is_scam": True, "sender": "+919876543221",
     "body": "CONGRATS! Your number has won our lucky draw. Claim your gift now: http://bit.ly/luckydraw2",
     "is_saved_contact": False},

    # ---- Borderline legit promotional (is_scam = False, tests false-positive rate) ----
    {"category": "legit_promo", "is_scam": False, "sender": "MYNTRA",
     "body": "Flat 40% off on your favorite brands this weekend only. Shop now on the Myntra app.",
     "is_saved_contact": False},
    {"category": "legit_bank_notice", "is_scam": False, "sender": "HDFCBK",
     "body": "Your HDFC Bank account balance as of today is Rs 12,500.",
     "is_saved_contact": False},
]


def build_request(case):
    return {
        "sender": case["sender"],
        "body": case["body"],
        "timestamp": int(time.time() * 1000),
        "source": "precision_recall_eval",
        "expected_otp": False,
        "foreground_app": "",
        "screen_unlocked": True,
        "is_saved_contact": case.get("is_saved_contact", False),
        "contact_name": case.get("contact_name"),
    }


def run_case(base_url, case):
    payload = build_request(case)
    try:
        resp = requests.post(base_url + ANALYZE_URL_PATH, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {"error": str(exc), "score": None, "status": None}

    analysis = data.get("analysis", {})
    score = analysis.get("score", analysis.get("risk_score"))
    status = analysis.get("status")
    return {"error": None, "score": score, "status": status, "raw": analysis}


# ============================================================================
# METRICS
# ============================================================================

def confusion_at_threshold(rows, threshold):
    tp = fp = tn = fn = 0
    for r in rows:
        if r["score"] is None:
            continue
        predicted_scam = r["score"] >= threshold
        actual_scam = r["is_scam"]
        if predicted_scam and actual_scam:
            tp += 1
        elif predicted_scam and not actual_scam:
            fp += 1
        elif not predicted_scam and actual_scam:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1, "accuracy": accuracy}


def print_confusion(m, threshold):
    print(f"\nThreshold: risk_score >= {threshold} counts as predicted SCAM")
    print(f"{'':>18}{'Predicted SCAM':>18}{'Predicted SAFE':>18}")
    print(f"{'Actual SCAM':>18}{m['tp']:>18}{m['fn']:>18}")
    print(f"{'Actual SAFE':>18}{m['fp']:>18}{m['tn']:>18}")
    print(f"\nPrecision: {m['precision']:.3f}   Recall: {m['recall']:.3f}   "
          f"F1: {m['f1']:.3f}   Accuracy: {m['accuracy']:.3f}")
    if m["fp"] > 0:
        print(f"-> {m['fp']} legitimate message(s) were wrongly flagged as scam (false positives).")
    if m["fn"] > 0:
        print(f"-> {m['fn']} actual scam message(s) were missed (false negatives) - the more")
        print("   dangerous error type for a security product.")


def main():
    parser = argparse.ArgumentParser(description="Precision/recall evaluation of /analyze-sms")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    print("=" * 78)
    print("PRECISION / RECALL EVALUATION - full pipeline (/analyze-sms)")
    print("=" * 78)
    print(f"Target: {base_url}{ANALYZE_URL_PATH}")
    print(f"Test messages: {len(TEST_CASES)}\n")

    rows = []
    for case in TEST_CASES:
        result = run_case(base_url, case)
        row = {**case, **result}
        rows.append(row)

        if result["error"]:
            print(f"[ERROR]  {case['category']:<24} {result['error']}")
            continue

        predicted_scam = (result["score"] or 0) >= CURRENT_THRESHOLD
        correct = predicted_scam == case["is_scam"]
        mark = "OK  " if correct else "MISS"
        print(f"[{mark}] {case['category']:<24} true={'SCAM' if case['is_scam'] else 'SAFE':<4} "
              f"score={result['score']:<4} status={result['status']}")

    usable_rows = [r for r in rows if r["score"] is not None]
    if not usable_rows:
        print("\nNo successful responses were received - is the backend running?")
        sys.exit(1)

    # ---- metrics at current threshold ----
    print("\n" + "-" * 78)
    print(f"METRICS AT CURRENT_THRESHOLD = {CURRENT_THRESHOLD}")
    print("-" * 78)
    m = confusion_at_threshold(usable_rows, CURRENT_THRESHOLD)
    print_confusion(m, CURRENT_THRESHOLD)

    # ---- threshold sweep ----
    print("\n" + "-" * 78)
    print("THRESHOLD SWEEP (0-100)")
    print("-" * 78)
    print(f"{'threshold':>10}{'precision':>12}{'recall':>10}{'f1':>10}")
    best = (None, -1.0)
    for t in range(0, 101, 5):
        sweep_m = confusion_at_threshold(usable_rows, t)
        marker = "  <- current" if t == CURRENT_THRESHOLD else ""
        print(f"{t:>10}{sweep_m['precision']:>12.3f}{sweep_m['recall']:>10.3f}{sweep_m['f1']:>10.3f}{marker}")
        if sweep_m["f1"] > best[1]:
            best = (t, sweep_m["f1"])
    print(f"\nBest F1 on this test set: threshold={best[0]} (F1={best[1]:.3f})")
    print("(Small hand-built set - treat this as a sanity check on where your")
    print(" threshold sits, not a precise tuning result. Re-run with real")
    print(" reported messages from your logs for a trustworthy number.)")

    # ---- misclassifications ----
    misses = [r for r in usable_rows if (r["score"] >= CURRENT_THRESHOLD) != r["is_scam"]]
    if misses:
        print("\n" + "-" * 78)
        print(f"MISCLASSIFIED AT CURRENT THRESHOLD ({len(misses)})")
        print("-" * 78)
        for r in misses:
            actual = "SCAM" if r["is_scam"] else "SAFE"
            predicted = "SCAM" if r["score"] >= CURRENT_THRESHOLD else "SAFE"
            print(f"  [{r['category']}] actual={actual} predicted={predicted} "
                  f"score={r['score']} status={r['status']}")
            print(f"    \"{r['body'][:90]}\"")

    # ---- save CSV ----
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "category", "is_scam", "sender", "body", "score", "status",
            "predicted_scam_at_current_threshold", "correct",
        ])
        writer.writeheader()
        for r in rows:
            predicted = (r.get("score") or 0) >= CURRENT_THRESHOLD if r.get("score") is not None else None
            writer.writerow({
                "category": r["category"],
                "is_scam": r["is_scam"],
                "sender": r["sender"],
                "body": r["body"],
                "score": r.get("score"),
                "status": r.get("status"),
                "predicted_scam_at_current_threshold": predicted,
                "correct": (predicted == r["is_scam"]) if predicted is not None else None,
            })
    print(f"\nFull results saved to: {OUT_CSV}")


if __name__ == "__main__":
    main()