"""
plot_family_heatmap.py

Reads embedding_similarity_matrix.csv (produced by
evaluate_embedding_quality.py) and draws a small, paper-friendly heatmap:
one cell per FAMILY PAIR (e.g. bank_kyc vs lottery_prize), showing the
average cosine similarity across all message pairs in that combination,
with the number printed inside each cell. Diagonal cells = average
within-family similarity (paraphrases of the same scam). Off-diagonal =
average across different families/legit.

This avoids the 19x19 unreadable grid: with 5 families you get a clean
5x5 grid, each cell labelled with its value, so it reproduces well at
paper size/DPI.

WHERE TO PUT IT:   backend/plot_family_heatmap.py  (same folder as the CSV)
HOW TO RUN:        python plot_family_heatmap.py
REQUIRES:          the CSV already exists (run evaluate_embedding_quality.py first)
                   pip install matplotlib numpy pandas   (pandas optional - falls
                   back to the csv module if pandas isn't installed)

Output: embedding_family_heatmap.png
"""

import csv
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CSV_PATH = HERE / "embedding_similarity_matrix.csv"
OUT_PNG = HERE / "embedding_family_heatmap.png"


def load_rows():
    if not CSV_PATH.exists():
        print(f"Could not find {CSV_PATH}.")
        print("Run evaluate_embedding_quality.py first to generate it.")
        sys.exit(1)

    rows = []
    with CSV_PATH.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({
                "family_a": r["family_a"],
                "family_b": r["family_b"],
                "similarity": float(r["similarity"]),
            })
    return rows


def build_family_matrix(rows):
    families = sorted({r["family_a"] for r in rows} | {r["family_b"] for r in rows})
    # Put LEGIT last for a cleaner read
    if "LEGIT" in families:
        families = [f for f in families if f != "LEGIT"] + ["LEGIT"]

    idx = {f: i for i, f in enumerate(families)}
    n = len(families)
    total = [[0.0] * n for _ in range(n)]
    count = [[0] * n for _ in range(n)]

    for r in rows:
        i, j = idx[r["family_a"]], idx[r["family_b"]]
        total[i][j] += r["similarity"]
        count[i][j] += 1
        if i != j:
            total[j][i] += r["similarity"]
            count[j][i] += 1

    matrix = [[(total[i][j] / count[i][j]) if count[i][j] else float("nan")
               for j in range(n)] for i in range(n)]

    return families, matrix


def plot(families, matrix):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("matplotlib/numpy are required for this script: pip install matplotlib numpy")
        sys.exit(1)

    n = len(families)
    arr = np.array(matrix)

    fig, ax = plt.subplots(figsize=(6.5, 5.5))
    im = ax.imshow(arr, vmin=0, vmax=1, cmap="viridis")

    ax.set_xticks(range(n))
    ax.set_yticks(range(n))
    ax.set_xticklabels(families, rotation=30, ha="right", fontsize=11)
    ax.set_yticklabels(families, fontsize=11)

    # annotate each cell with its value; flip text color for readability
    for i in range(n):
        for j in range(n):
            value = arr[i, j]
            color = "white" if value < 0.55 else "black"
            ax.text(j, i, f"{value:.2f}", ha="center", va="center",
                     color=color, fontsize=11, fontweight="bold")

    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label("avg. cosine similarity", fontsize=11)
    cbar.ax.tick_params(labelsize=10)

    ax.set_title("Average pairwise embedding similarity by scam family",
                 fontsize=13, pad=12)
    fig.tight_layout()
    fig.savefig(OUT_PNG, dpi=300, bbox_inches="tight")
    print(f"Saved: {OUT_PNG}")


def main():
    rows = load_rows()
    families, matrix = build_family_matrix(rows)
    print("Families found:", families)
    plot(families, matrix)


if __name__ == "__main__":
    main()