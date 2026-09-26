"""
measure_fastpath_latency.py

Measures ONLY the "semantic fast-path" case: a message whose embedding
matches an existing pattern that has already been seen 5+ times
(SPAM_OCCURRENCE_THRESHOLD) and is therefore CONFIRMED_SPAM. In that
case main.py returns immediately after semantic_precheck() and never
runs the LangGraph agents (OTP / URL / Contact) at all.

This script breaks that path down into:
    1. generate_embedding      - turning the SMS text into a vector
    2. db_lookup                - reading every doc from spam_patterns
                                   and comparing similarity (_find_best_pattern)
    3. pattern_status_lookup    - reading the append-only event log to
                                   get CONFIRMED_SPAM / PENDING (_get_pattern_status)
    4. persist_message          - writing the message_records entry
    5. TOTAL fast-path time     - everything above, i.e. semantic_precheck()
                                   end to end

If a message does NOT hit the fast path (new pattern, or pattern not yet
confirmed), this script still shows the semantic-precheck breakdown but
clearly labels it "NOT fast-path (fell through to LangGraph)" so you
don't mix the two cases together.

WHERE TO PUT IT:   backend/measure_fastpath_latency.py
HOW TO RUN:        cd backend
                   python measure_fastpath_latency.py
                   (use this INSTEAD of `uvicorn app.main:app ...`)

Every request to /analyze-sms is still served normally (fast-path or
full LangGraph, whichever applies) - this only adds timing.

Only fast-path hits are written to fastpath_latency_log.csv, since
that's the specific number you asked for. The Ctrl+C summary reports
the average/min/max/p95 fast-path time over however many fast-path
hits occurred.
"""

import csv
import functools
import json
import statistics
import sys
import threading
import time
from datetime import datetime
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

HOST = "0.0.0.0"
PORT = 8000
CSV_PATH = HERE / "fastpath_latency_log.csv"
TARGET_PATH = "/analyze-sms"

try:
    from app import main as m
except Exception as exc:  # pragma: no cover
    print("Could not import app.main. Run this file from the backend/ folder.")
    print(f"{type(exc).__name__}: {exc}")
    raise

import uvicorn
import app.services.semantic_spam_service as svc

# ============================================================================
# STAGE TIMING (per-request, thread-local-ish via a simple list + lock)
# ============================================================================

_EVENTS = []
_EVENTS_LOCK = threading.Lock()


def _timed(stage, fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        t0 = time.perf_counter()
        try:
            return fn(*args, **kwargs)
        finally:
            t1 = time.perf_counter()
            with _EVENTS_LOCK:
                _EVENTS.append((stage, t0, t1))

    return wrapper


def install_instrumentation():
    # generate_embedding is imported directly into semantic_spam_service's
    # namespace ("from ... import generate_embedding"), so patch it there,
    # not on the original embedding_service module.
    svc.generate_embedding = _timed("1_generate_embedding", svc.generate_embedding)
    svc._safe_embedding = _timed("1_generate_embedding_safe_wrap", svc._safe_embedding)
    svc._find_best_pattern = _timed("2_db_lookup_similarity", svc._find_best_pattern)
    svc._get_pattern_status = _timed("3_pattern_status_lookup", svc._get_pattern_status)
    svc._persist_message = _timed("4_persist_message", svc._persist_message)
    svc._increment_pattern = _timed("_increment_pattern (non-fastpath)", svc._increment_pattern)
    svc._create_new_pattern = _timed("_create_new_pattern (non-fastpath)", svc._create_new_pattern)

    # Time semantic_precheck() itself as used by main.py
    m.semantic_precheck = _timed("TOTAL_semantic_precheck", m.semantic_precheck)


# ============================================================================
# MIDDLEWARE
# ============================================================================

_FASTPATH_ROWS = []
_ALL_PRECHECK_ROWS = []
_REQUEST_COUNTER = 0

CSV_FIELDS = [
    "time", "n", "sender", "fastpath_total_ms",
    "generate_embedding_ms", "db_lookup_similarity_ms",
    "pattern_status_lookup_ms", "persist_message_ms",
]


def _ms(seconds):
    return round(seconds * 1000.0, 2)


def _write_csv(row):
    new_file = not CSV_PATH.exists()
    with CSV_PATH.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if new_file:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in CSV_FIELDS})


@m.app.middleware("http")
async def fastpath_latency_middleware(request, call_next):
    global _REQUEST_COUNTER

    if request.method != "POST" or request.url.path != TARGET_PATH:
        return await call_next(request)

    sender = "?"
    try:
        raw = await request.body()
        payload = json.loads(raw or b"{}")
        sender = payload.get("sender", "?")
    except Exception:
        pass

    with _EVENTS_LOCK:
        _EVENTS.clear()

    t_start = time.perf_counter()
    response = await call_next(request)
    t_end = time.perf_counter()

    with _EVENTS_LOCK:
        events = [e for e in _EVENTS if e[1] >= t_start and e[2] <= t_end + 0.05]
        _EVENTS.clear()

    _REQUEST_COUNTER += 1
    n = _REQUEST_COUNTER

    durations = {}
    for stage, s, e in events:
        durations[stage] = durations.get(stage, 0.0) + (e - s)

    precheck_total = durations.get("TOTAL_semantic_precheck")
    # Fast path = a request that never entered LangGraph, i.e. no
    # pattern-creation/increment work ran and semantic_precheck alone
    # accounts for (essentially) the whole request time.
    is_fastpath = (
        precheck_total is not None
        and "_increment_pattern (non-fastpath)" not in durations
        and "_create_new_pattern (non-fastpath)" not in durations
    )

    line = "=" * 72
    if is_fastpath:
        print(f"\n{line}\nFAST-PATH SPAM MATCH  SMS #{n}   sender={sender}\n{line}")
        print("(Pattern already CONFIRMED_SPAM - skipped LangGraph entirely)\n")

        embed_ms = _ms(durations.get("1_generate_embedding", 0.0)) or _ms(durations.get("1_generate_embedding_safe_wrap", 0.0))
        db_ms = _ms(durations.get("2_db_lookup_similarity", 0.0))
        status_ms = _ms(durations.get("3_pattern_status_lookup", 0.0))
        persist_ms = _ms(durations.get("4_persist_message", 0.0))
        total_ms = _ms(precheck_total)

        print(f"{'Step':<38}{'duration':>12}")
        print("-" * 50)
        print(f"{'1. Generate semantic embedding':<38}{embed_ms:>9.2f} ms")
        print(f"{'2. DB lookup + similarity compare':<38}{db_ms:>9.2f} ms")
        print(f"{'3. Pattern status lookup (CONFIRMED?)':<38}{status_ms:>9.2f} ms")
        print(f"{'4. Persist message record':<38}{persist_ms:>9.2f} ms")
        print("-" * 50)
        print(f"{'TOTAL fast-path time':<38}{total_ms:>9.2f} ms  ({total_ms / 1000:.3f} s)")
        print("(This is the complete time: message in -> classified SPAM, no agents run.)")

        row = {
            "time": datetime.now().isoformat(timespec="seconds"),
            "n": n,
            "sender": sender,
            "fastpath_total_ms": total_ms,
            "generate_embedding_ms": embed_ms,
            "db_lookup_similarity_ms": db_ms,
            "pattern_status_lookup_ms": status_ms,
            "persist_message_ms": persist_ms,
        }
        _FASTPATH_ROWS.append(row)
        try:
            _write_csv(row)
        except Exception as exc:
            print(f"[fastpath-latency] could not write CSV: {exc}")
    else:
        precheck_ms = _ms(precheck_total) if precheck_total is not None else None
        print(f"\n{line}\nNOT fast-path  SMS #{n}   sender={sender}  "
              f"(new/unconfirmed pattern - fell through to LangGraph)\n{line}")
        if precheck_ms is not None:
            print(f"Semantic precheck step took: {precheck_ms:.2f} ms before LangGraph ran.")

    if precheck_total is not None:
        _ALL_PRECHECK_ROWS.append(_ms(precheck_total))

    return response


# ============================================================================
# SUMMARY
# ============================================================================

def _percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct / 100.0
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def print_summary():
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)

    if _FASTPATH_ROWS:
        totals = [r["fastpath_total_ms"] for r in _FASTPATH_ROWS]
        print(f"\nFast-path (confirmed-spam, no LangGraph) hits: {len(totals)}")
        print(f"  Average : {statistics.mean(totals):>9.2f} ms")
        print(f"  Minimum : {min(totals):>9.2f} ms")
        print(f"  Maximum : {max(totals):>9.2f} ms")
        print(f"  Median  : {_percentile(totals, 50):>9.2f} ms")
        print(f"  P95     : {_percentile(totals, 95):>9.2f} ms")

        for label, key in (
            ("  Embedding avg", "generate_embedding_ms"),
            ("  DB lookup avg", "db_lookup_similarity_ms"),
            ("  Status lookup avg", "pattern_status_lookup_ms"),
            ("  Persist avg", "persist_message_ms"),
        ):
            vals = [r[key] for r in _FASTPATH_ROWS if r[key]]
            if vals:
                print(f"{label:<21}: {statistics.mean(vals):>9.2f} ms")

        print(f"\nFast-path details saved in: {CSV_PATH}")
    else:
        print("\nNo fast-path (already-confirmed-spam) hits occurred during this run.")
        print("To trigger one: send the SAME (or very similar) spam-style message")
        print("5+ times in a row so its pattern crosses SPAM_OCCURRENCE_THRESHOLD,")
        print("then send it a 6th time - that 6th request is the fast-path hit.")

    if _ALL_PRECHECK_ROWS:
        print(f"\n(For reference: semantic_precheck ran {len(_ALL_PRECHECK_ROWS)} times total, "
              f"avg {statistics.mean(_ALL_PRECHECK_ROWS):.2f} ms, "
              f"including non-fast-path calls.)")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    install_instrumentation()
    print(f"\n[fastpath-latency] Backend starting on http://{HOST}:{PORT}")
    print("[fastpath-latency] Send SMS as usual. Only fast-path hits are logged to CSV.")
    print("[fastpath-latency] Ctrl+C to stop and see the summary.\n")
    try:
        uvicorn.run(m.app, host=HOST, port=PORT, log_level="info")
    finally:
        print_summary()