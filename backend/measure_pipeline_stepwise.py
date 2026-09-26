"""
measure_pipeline_stepwise.py

Full stepwise timing of the whole /analyze-sms pipeline, in the order
things actually happen:

    1. Phone -> server transit          (approximate, see note below)
    2. Semantic gate
         2a. generate embedding
         2b. DB lookup + similarity compare (spam_patterns)
         2c. pattern status lookup (CONFIRMED_SPAM? via pattern_events)
         2d. persist message_records entry
       -> if the pattern is already CONFIRMED_SPAM, the pipeline STOPS
          here and returns SPAM immediately (fast path, no LangGraph)
    3. LangGraph (only runs if step 2 did not already return)
         3a. OTP agent           (+ its own timing, no separate Mongo write)
         3b. URL agent           (+ its own timing, no separate Mongo write)
         3c. Contact agent, including its 2 MongoDB writes:
               - record_sender_activity   (senders collection upsert)
               - record_message_analysis  (message_analyses collection insert)
       (3a/3b/3c run IN PARALLEL inside LangGraph - their times overlap)
    4. TOTAL backend time                (request received -> response sent)

Every step is printed as it happens, then a full waterfall summary per
SMS, then a Ctrl+C summary across all SMS with per-step averages, so you
can see exactly where the time goes.

WHERE TO PUT IT:   backend/measure_pipeline_stepwise.py
HOW TO RUN:        cd backend
                   python measure_pipeline_stepwise.py
                   (use this INSTEAD of `uvicorn app.main:app ...` while measuring)

Then send an SMS from the other phone as usual - nothing else changes.
Everything is also appended to pipeline_stepwise_log.csv.

NOTES
-----
* "Phone -> server transit" = server receive time minus the `timestamp`
  SmsReceiver.kt puts in the request. Only meaningful if the phone clock
  and this PC's clock are in sync; an emulator usually is, a physical
  phone may be off by seconds - unreliable values are flagged, not hidden.
* The first SMS after startup is slower (model load, first Mongo
  connection, cold HTTP connections to Groq). Send one warm-up SMS first
  and treat it separately from your reported numbers.
* Steps 3a/3b/3c overlap (LangGraph runs agents in parallel via Send()),
  so their individual durations will NOT sum to the LangGraph total -
  that's expected, not a measurement error.
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
CSV_PATH = HERE / "pipeline_stepwise_log.csv"
TARGET_PATH = "/analyze-sms"

try:
    from app import main as m
except Exception as exc:  # pragma: no cover
    print("Could not import app.main. Run this file from the backend/ folder.")
    print(f"{type(exc).__name__}: {exc}")
    raise

import uvicorn
import app.services.semantic_spam_service as svc
import agents.langgraph_coordinator as lg
import agents.contact.reputation as reputation_mod

# ============================================================================
# INSTRUMENTATION
# ============================================================================

_EVENTS = []
_EVENTS_LOCK = threading.Lock()

# Ordered list of (display_label, internal_stage_key) for the waterfall print
STEP_ORDER = [
    ("Semantic: generate embedding",        "sem.embedding"),
    ("Semantic: DB lookup + similarity",     "sem.db_lookup"),
    ("Semantic: pattern status lookup",      "sem.status_lookup"),
    ("Semantic: persist message record",     "sem.persist_message"),
    ("Semantic gate TOTAL",                  "sem.total"),
    ("LangGraph: OTP agent",                 "agent.otp"),
    ("LangGraph: URL agent",                 "agent.url"),
    ("LangGraph: Contact agent",             "agent.contact"),
    ("  Contact -> Mongo: sender upsert",    "mongo.sender_activity"),
    ("  Contact -> Mongo: message insert",   "mongo.message_analysis"),
    ("LangGraph TOTAL",                      "langgraph.total"),
]


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


class _GraphProxy:
    """Wraps the compiled LangGraph so the whole run is timed as one stage."""

    def __init__(self, graph):
        self._graph = graph

    def invoke(self, *args, **kwargs):
        t0 = time.perf_counter()
        try:
            return self._graph.invoke(*args, **kwargs)
        finally:
            with _EVENTS_LOCK:
                _EVENTS.append(("langgraph.total", t0, time.perf_counter()))

    def __getattr__(self, name):
        return getattr(self._graph, name)


def install_instrumentation():
    # ---- semantic gate sub-steps ----
    svc.generate_embedding = _timed("sem.embedding", svc.generate_embedding)
    svc._safe_embedding = _timed("sem.embedding", svc._safe_embedding)
    svc._find_best_pattern = _timed("sem.db_lookup", svc._find_best_pattern)
    svc._get_pattern_status = _timed("sem.status_lookup", svc._get_pattern_status)
    svc._persist_message = _timed("sem.persist_message", svc._persist_message)
    m.semantic_precheck = _timed("sem.total", m.semantic_precheck)

    # ---- LangGraph total ----
    if getattr(m, "scam_graph", None) is not None:
        m.scam_graph = _GraphProxy(m.scam_graph)

    # ---- per-agent (as called from the LangGraph node functions) ----
    lg.analyze_otp = _timed("agent.otp", lg.analyze_otp)
    lg.analyze_url = _timed("agent.url", lg.analyze_url)
    lg.analyze_contact = _timed("agent.contact", lg.analyze_contact)

    # ---- MongoDB writes made by the Contact agent ----
    reputation_mod.record_sender_activity = _timed(
        "mongo.sender_activity", reputation_mod.record_sender_activity)
    reputation_mod.record_message_analysis = _timed(
        "mongo.message_analysis", reputation_mod.record_message_analysis)

    # contact_agent.py does `from .contact import reputation as contact_reputation`
    # and calls contact_reputation.record_sender_activity(...), so patching the
    # reputation module's own attributes (above) is enough - no need to patch
    # a second reference in contact_agent's namespace.


# ============================================================================
# MIDDLEWARE
# ============================================================================

_ROWS = []
_REQUEST_COUNTER = 0

CSV_FIELDS = ["time", "n", "sender", "fast_path", "phone_to_server_ms", "total_backend_ms"] + \
             [key for _, key in STEP_ORDER]


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
async def stepwise_latency_middleware(request, call_next):
    global _REQUEST_COUNTER

    if request.method != "POST" or request.url.path != TARGET_PATH:
        return await call_next(request)

    recv_wall_ms = time.time() * 1000.0

    sender = "?"
    phone_ts = None
    try:
        raw = await request.body()
        payload = json.loads(raw or b"{}")
        sender = payload.get("sender", "?")
        phone_ts = payload.get("timestamp")
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
    total_ms = _ms(t_end - t_start)

    durations = {}
    for stage, s, e in events:
        durations[stage] = durations.get(stage, 0.0) + (e - s)

    fast_path = "langgraph.total" not in durations

    # ---- phone -> server transit (approximate) ----
    transit_ms = None
    transit_note = ""
    if isinstance(phone_ts, (int, float)) and phone_ts > 0:
        transit_ms = round(recv_wall_ms - float(phone_ts), 1)
        if transit_ms < 0 or transit_ms > 60_000:
            transit_note = "  (unreliable: phone/PC clocks not in sync)"

    # ---- print waterfall ----
    line = "=" * 72
    print(f"\n{line}\nPIPELINE TIMING  SMS #{n}   sender={sender}\n{line}")
    if transit_ms is not None:
        print(f"1. Phone -> server transit          : {transit_ms:>9.1f} ms{transit_note}")
    else:
        print("1. Phone -> server transit          :   n/a (no phone timestamp on this request)")

    print("-" * 72)
    for label, key in STEP_ORDER:
        if key in durations:
            print(f"{label:<37}: {_ms(durations[key]):>9.1f} ms")
    print("-" * 72)
    if fast_path:
        print("(Semantic fast-path hit: pattern already CONFIRMED_SPAM - LangGraph skipped)")
    else:
        print("(OTP / URL / Contact agents run in parallel - their times overlap; use")
        print(" 'LangGraph TOTAL' for the real wall-clock time of that stage.)")
    print(f"\nTOTAL: message received -> output ready : {total_ms:>9.1f} ms  ({total_ms / 1000:.2f} s)")

    row = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "n": n,
        "sender": sender,
        "fast_path": fast_path,
        "phone_to_server_ms": transit_ms if transit_ms is not None else "",
        "total_backend_ms": total_ms,
    }
    for _, key in STEP_ORDER:
        row[key] = _ms(durations[key]) if key in durations else ""
    _ROWS.append(row)
    try:
        _write_csv(row)
    except Exception as exc:
        print(f"[pipeline-timing] could not write CSV: {exc}")

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
    if not _ROWS:
        print("\nNo SMS were analyzed during this run.")
        return

    totals = [r["total_backend_ms"] for r in _ROWS]
    print("\n" + "=" * 72)
    print(f"SUMMARY  ({len(totals)} SMS analyzed)")
    print("=" * 72)
    print(f"Average TOTAL : {statistics.mean(totals):>9.1f} ms")
    print(f"Minimum TOTAL : {min(totals):>9.1f} ms")
    print(f"Maximum TOTAL : {max(totals):>9.1f} ms")
    print(f"Median  TOTAL : {_percentile(totals, 50):>9.1f} ms")
    print(f"P95     TOTAL : {_percentile(totals, 95):>9.1f} ms")

    fast_count = sum(1 for r in _ROWS if r["fast_path"])
    print(f"\nFast-path hits (skipped LangGraph): {fast_count} / {len(_ROWS)}")

    print("\nPer-step averages (over SMS where that step ran):")
    for label, key in STEP_ORDER:
        vals = [r[key] for r in _ROWS if isinstance(r.get(key), (int, float))]
        if vals:
            print(f"  {label:<37}: {statistics.mean(vals):>9.1f} ms  (n={len(vals)})")

    transits = [r["phone_to_server_ms"] for r in _ROWS
                if isinstance(r["phone_to_server_ms"], (int, float)) and 0 <= r["phone_to_server_ms"] <= 60_000]
    if transits:
        print(f"\nPhone -> server transit avg          : {statistics.mean(transits):>9.1f} ms")

    print(f"\nFull per-SMS details saved in: {CSV_PATH}")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    install_instrumentation()
    print(f"\n[pipeline-timing] Backend starting on http://{HOST}:{PORT}")
    print("[pipeline-timing] Send an SMS to the phone. Results appear here. Ctrl+C to stop.\n")
    try:
        uvicorn.run(m.app, host=HOST, port=PORT, log_level="info")
    finally:
        print_summary()