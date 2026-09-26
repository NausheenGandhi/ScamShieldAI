"""
evaluate_embedding_quality.py

Answers: "is the semantic embedding actually good at its job?"

Its job (per app/services/semantic_spam_service.py) is: given a new SMS,
decide whether it's a reworded copy of a scam pattern already seen, using
cosine similarity between MiniLM embeddings, at
SEMANTIC_SIMILARITY_THRESHOLD (default 0.70).

This script builds a small labeled test set with three kinds of message:
    - SAME-FAMILY pairs   : two different wordings of the SAME scam
                             (e.g. two phrasings of a "KYC will be
                             blocked" bank scam) -> SHOULD be judged
                             similar (match).
    - CROSS-FAMILY pairs   : two DIFFERENT scam templates (e.g. a bank
                             KYC scam vs a lottery-prize scam) -> SHOULD
                             be judged NOT similar.
    - LEGIT vs anything     : an ordinary, non-scam message compared
                             against every scam message -> SHOULD be
                             judged NOT similar.

It runs your project's actual normalization + embedding pipeline
(the same _normalize_for_embedding / generate_embedding used in
production), then reports:

    1. Whether the REAL model or the SHA-256 FALLBACK is active
       (the fallback is not a semantic embedding at all - if this
       script says fallback is active, the similarity numbers below
       are meaningless and sentence-transformers needs to be installed)
    2. Average cosine similarity within same-family pairs (want: high)
    3. Average cosine similarity across different families (want: low)
    4. Average cosine similarity legit-vs-scam (want: low)
    5. Separation margin = (3) minus the higher of (4)/(5)  (want: large, positive)
    6. Precision/recall/F1 of the CURRENT threshold (0.70) at telling
       same-family pairs apart from everything else
    7. A sweep over thresholds 0.50-0.95 showing which threshold would
       maximize F1 on this test set, so you can see if 0.70 is well-chosen
    8. A full pairwise similarity matrix saved to a CSV for manual inspection
    9. If matplotlib is installed, a similarity heatmap PNG

WHERE TO PUT IT:   backend/evaluate_embedding_quality.py
HOW TO RUN:        cd backend
                   python evaluate_embedding_quality.py

You can freely edit TEST_MESSAGES below to add real messages from your
own logs (recommended once you have real user-reported scam text) - the
built-in set is just a representative starting point.
"""

import csv
import itertools
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

try:
    from dotenv import load_dotenv
    for candidate in (HERE / ".env", HERE / "app" / ".env"):
        if candidate.exists():
            load_dotenv(candidate)
except ImportError:
    pass

from app.services.embedding_service import generate_embedding, load_embedding_model
from app.services.semantic_spam_service import _normalize_for_embedding, DEFAULT_SIMILARITY_THRESHOLD

OUT_CSV = HERE / "embedding_similarity_matrix.csv"
OUT_PNG = HERE / "embedding_similarity_heatmap.png"

# ============================================================================
# TEST SET
# family: a short label grouping paraphrases of the SAME scam template.
# family "LEGIT" messages are ordinary, non-scam texts.
# ============================================================================

TEST_MESSAGES = [
    # --- Family: bank KYC/account-block scam, reworded 4 ways ---
    ("bank_kyc", "Dear customer, your bank account will be blocked today. Complete your KYC immediately: http://bit.ly/kyc123"),
    ("bank_kyc", "URGENT: Your account will be suspended within 24 hours. Update your KYC now at http://verify-kyc.example/link"),
    ("bank_kyc", "Your a/c will be deactivated due to pending KYC. Click here to update: http://kyc-update.example/x"),
    ("bank_kyc", "Alert! KYC verification pending, account block hoga aaj. Verify now: http://bit.ly/kycnow"),

    # --- Family: lottery / prize scam, reworded 4 ways ---
    ("lottery_prize", "Congratulations! You have won a lucky draw prize of Rs 5,00,000. Claim now: http://bit.ly/claimprize"),
    ("lottery_prize", "You are today's lucky winner! Claim your reward of 5 lakh rupees here: http://prize-claim.example/win"),
    ("lottery_prize", "CONGRATS! Your mobile number has won our lucky draw. Claim your gift now: http://bit.ly/luckydraw2"),
    ("lottery_prize", "You've been selected as a lucky winner of a cash prize! Click to claim your reward: http://win-now.example/"),

    # --- Family: delivery/customs-fee scam, reworded 3 ways ---
    ("delivery_fee", "Your parcel is on hold due to unpaid customs duty. Pay Rs 199 now to release delivery: http://bit.ly/custfee"),
    ("delivery_fee", "Package could not be delivered - outstanding customs fee required. Pay now: http://delivery-fee.example/pay"),
    ("delivery_fee", "Your courier is held at the warehouse, pending customs charges. Settle payment here: http://bit.ly/pkgfee"),

    # --- Family: OTP/credential phishing, reworded 3 ways ---
    ("otp_phish", "Your account was accessed from a new device. Enter the OTP sent to you to secure your account immediately: http://sec-check.example/"),
    ("otp_phish", "Unusual login detected on your account. Verify with the OTP you received to prevent unauthorized access: http://verify-login.example/"),
    ("otp_phish", "Security alert: confirm it's you. Use the OTP just sent to validate your identity now: http://bit.ly/confirmid"),

    # --- LEGIT ordinary messages (not scams at all) ---
    ("LEGIT", "Hey, are we still meeting for lunch at 1pm today?"),
    ("LEGIT", "Your Swiggy order has been delivered. Enjoy your meal!"),
    ("LEGIT", "Reminder: your dentist appointment is tomorrow at 10am."),
    ("LEGIT", "Mom, I'll be home a bit late tonight, don't wait up for dinner."),
    ("LEGIT", "Your electricity bill of Rs 1,240 for this month is now available to view in the app."),
]


def cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(x * x for x in b) ** 0.5
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


def check_model_is_real():
    model = load_embedding_model()
    is_fallback = type(model).__name__ == "_FallbackModel"
    return is_fallback, type(model).__name__


def main():
    print("=" * 78)
    print("EMBEDDING QUALITY EVALUATION")
    print("=" * 78)

    is_fallback, model_class = check_model_is_real()
    if is_fallback:
        print(f"\n*** WARNING: sentence-transformers is NOT active. ***")
        print(f"Model in use: {model_class} (a hash-based stand-in, not a real")
        print("semantic embedding). Every similarity number below will be")
        print("close to random and this evaluation is not meaningful until")
        print("you `pip install sentence-transformers` and restart.\n")
    else:
        print(f"\nModel in use: {model_class}  (real semantic embedding - good)\n")

    # ---- embed everything (using the SAME normalization prod uses) ----
    print(f"Embedding {len(TEST_MESSAGES)} test messages...")
    records = []
    for family, text in TEST_MESSAGES:
        cleaned = _normalize_for_embedding(text)
        vec = [float(v) for v in generate_embedding(cleaned)]
        records.append({"family": family, "text": text, "cleaned": cleaned, "vec": vec})

    # ---- pairwise similarity ----
    pairs = []
    for a, b in itertools.combinations(records, 2):
        sim = cosine(a["vec"], b["vec"])
        same_family = (a["family"] == b["family"]) and a["family"] != "LEGIT"
        involves_legit = a["family"] == "LEGIT" or b["family"] == "LEGIT"
        pairs.append({
            "text_a": a["text"], "family_a": a["family"],
            "text_b": b["text"], "family_b": b["family"],
            "similarity": round(sim, 4),
            "same_family": same_family,
            "involves_legit": involves_legit,
        })

    same_family_sims = [p["similarity"] for p in pairs if p["same_family"]]
    cross_family_sims = [p["similarity"] for p in pairs
                          if not p["same_family"] and not p["involves_legit"]]
    legit_sims = [p["similarity"] for p in pairs if p["involves_legit"]]

    def avg(values):
        return sum(values) / len(values) if values else 0.0

    print("\n" + "-" * 78)
    print("SEPARATION (higher same-family avg, lower everything-else avg = better)")
    print("-" * 78)
    print(f"Same scam family, reworded   (n={len(same_family_sims):>3}): avg similarity = {avg(same_family_sims):.4f}")
    print(f"Different scam families      (n={len(cross_family_sims):>3}): avg similarity = {avg(cross_family_sims):.4f}")
    print(f"Legit message vs anything    (n={len(legit_sims):>3}): avg similarity = {avg(legit_sims):.4f}")

    worst_other = max(avg(cross_family_sims), avg(legit_sims))
    margin = avg(same_family_sims) - worst_other
    print(f"\nSeparation margin (same-family avg minus worst other-group avg): {margin:+.4f}")
    if margin > 0.15:
        print("  -> Good separation: paraphrases cluster well above unrelated text.")
    elif margin > 0.05:
        print("  -> Weak separation: the model distinguishes paraphrases only a little.")
    else:
        print("  -> Poor/no separation: the embedding is not reliably telling paraphrases")
        print("     of the same scam apart from unrelated messages.")

    # ---- current threshold performance ----
    threshold = DEFAULT_SIMILARITY_THRESHOLD
    print("\n" + "-" * 78)
    print(f"CURRENT THRESHOLD PERFORMANCE (SEMANTIC_SIMILARITY_THRESHOLD = {threshold})")
    print("-" * 78)
    _report_threshold(pairs, threshold)

    # ---- threshold sweep ----
    print("\n" + "-" * 78)
    print("THRESHOLD SWEEP (which cutoff best separates same-family from the rest)")
    print("-" * 78)
    print(f"{'threshold':>10}{'precision':>12}{'recall':>10}{'f1':>10}")
    best = (None, -1.0)
    for t in [round(0.50 + 0.025 * i, 3) for i in range(19)]:
        p, r, f1, _, _, _, _ = _prf(pairs, t)
        marker = "  <- current" if abs(t - threshold) < 0.0126 else ""
        print(f"{t:>10.3f}{p:>12.3f}{r:>10.3f}{f1:>10.3f}{marker}")
        if f1 > best[1]:
            best = (t, f1)
    print(f"\nBest F1 on this test set: threshold={best[0]} (F1={best[1]:.3f})")
    print("(This is a small hand-built set - treat this as a sanity check on the")
    print(" threshold's ballpark, not a precise tuning result. Re-run with real")
    print(" reported-scam text from your logs for a trustworthy number.)")

    # ---- save full matrix ----
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "family_a", "text_a", "family_b", "text_b", "similarity", "same_family", "involves_legit"
        ])
        writer.writeheader()
        for p in sorted(pairs, key=lambda x: -x["similarity"]):
            writer.writerow(p)
    print(f"\nFull pairwise similarity matrix saved to: {OUT_CSV}")

    _maybe_plot_heatmap(records)


def _classify(sim, threshold):
    # Mirrors semantic_spam_service's primary cosine-threshold decision
    # (the token-overlap fallback-match rescue depends on the full corpus,
    # not just a pair, so it is not modeled at the pair level here).
    return sim >= threshold


def _prf(pairs, threshold):
    tp = fp = tn = fn = 0
    for p in pairs:
        predicted_match = _classify(p["similarity"], threshold)
        actual_match = p["same_family"]
        if predicted_match and actual_match:
            tp += 1
        elif predicted_match and not actual_match:
            fp += 1
        elif not predicted_match and actual_match:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1, tp, fp, tn, fn


def _report_threshold(pairs, threshold):
    precision, recall, f1, tp, fp, tn, fn = _prf(pairs, threshold)
    print(f"True positives  (correctly matched paraphrases)      : {tp}")
    print(f"False positives (unrelated pairs wrongly matched)     : {fp}")
    print(f"True negatives  (correctly kept apart)                : {tn}")
    print(f"False negatives (paraphrases wrongly kept apart)      : {fn}")
    print(f"Precision: {precision:.3f}   Recall: {recall:.3f}   F1: {f1:.3f}")
    if fp > 0:
        print(f"-> {fp} unrelated message pair(s) would incorrectly be treated as the")
        print("   same scam pattern at this threshold - risk of over-grouping.")
    if fn > 0:
        print(f"-> {fn} true paraphrase pair(s) would be missed as a match at this")
        print("   threshold - risk of the same scam being tracked as separate patterns.")


def _maybe_plot_heatmap(records):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("\n(matplotlib not installed - skipping heatmap image; CSV above has full data)")
        return

    n = len(records)
    matrix = np.zeros((n, n))
    for i in range(n):
        for j in range(n):
            matrix[i, j] = cosine(records[i]["vec"], records[j]["vec"])

    labels = [f"{r['family']}" for r in records]
    fig, ax = plt.subplots(figsize=(10, 9))
    im = ax.imshow(matrix, vmin=0, vmax=1, cmap="viridis")
    ax.set_xticks(range(n))
    ax.set_yticks(range(n))
    ax.set_xticklabels(labels, rotation=90, fontsize=7)
    ax.set_yticklabels(labels, fontsize=7)
    fig.colorbar(im, label="cosine similarity")
    ax.set_title("Pairwise embedding similarity (blocks should be bright on-diagonal,\ndark off-diagonal, if the model separates families well)")
    fig.tight_layout()
    fig.savefig(OUT_PNG, dpi=150)
    print(f"\nSimilarity heatmap saved to: {OUT_PNG}")


if __name__ == "__main__":
    main()