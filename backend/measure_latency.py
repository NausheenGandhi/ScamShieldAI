"""
measure_latency.py

Starts your normal FastAPI backend (app.main:app) and measures how long
every incoming SMS takes to be fully analyzed.

WHERE TO PUT IT:   backend/measure_latency.py      (next to the app/ folder)
HOW TO RUN:        cd backend
                   python measure_latency.py
                   (use this INSTEAD of `uvicorn app.main:app ...`)

Then send an SMS from the other mobile as usual. For every SMS you get:

  * phone -> server transit time (approximate, see note below)
  * semantic gate time
  * total LangGraph time
  * time per agent (OTP / URL / Contact), and sub-steps such as
    WHOIS, redirect following, each Groq LLM call
  * TOTAL backend time  (request received -> response ready)

Everything is also appended to latency_log.csv. Press Ctrl+C to stop; a
summary (avg / min / max / p50 / p95) is printed.

NOTES
-----
* The agents run IN PARALLEL inside LangGraph, so agent times overlap and
  will not add up to the total. The TOTAL is the real wall-clock number.
* "phone -> server transit" = server receive time - the `timestamp` the
  Kotlin SmsReceiver puts in the request. It is only meaningful if the
  phone clock and this PC clock are in sync (an emulator usually is; a
  physical phone may be off by seconds). Nonsense values are flagged.
  That timestamp is taken AFTER the SMS arrives and after the contact /
  foreground-app lookups, so those few ms on the phone are not included.
* The first SMS after startup is usually slower (model load, Mongo
  connection, cold HTTP connections). Send a warm-up SMS first.
* Not measured here: the time for the app UI to pick up the result
  (App.js polls SharedPreferences every 2 s, so add up to ~2 s for the
  screen to update).
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

# ---- load .env the same way the project does -------------------------------
try:
    from dotenv import load_dotenv

    for candidate in (HERE / ".env", HERE / "app" / ".env"):
        if candidate.exists():
            load_dotenv(candidate)
except ImportError:
    pass

HOST = "0.0.0.0"
PORT = 8000
CSV_PATH = HERE / "latency_log.csv"
TARGET_PATH = "/analyze-sms"

# ---- import the real backend -----------------------------------------------
try:
    from app import main as m  # this also puts ai-engine on sys.path
except Exception as exc:  # pragma: no cover
    print("Could not import app.main. Run this file from the backend/ folder.")
    print(f"{type(exc).__name__}: {exc}")
    raise

import uvicorn

# ============================================================================
# STAGE TIMING
# ============================================================================

_EVENTS = []  # (stage_name, start_perf, end_perf)
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


def _patch(module, attr, stage):
    fn = getattr(module, attr, None)
    if fn is None:
        print(f"[latency] skip: {module.__name__}.{attr} not found")
        return
    setattr(module, attr, _timed(stage, fn))


class _GraphProxy:
    """Wraps the compiled LangGraph so its whole run is timed."""

    def __init__(self, graph):
        self._graph = graph

    def invoke(self, *args, **kwargs):
        t0 = time.perf_counter()
        try:
            return self._graph.invoke(*args, **kwargs)
        finally:
            with _EVENTS_LOCK:
                _EVENTS.append(("langgraph_total", t0, time.perf_counter()))

    def __getattr__(self, name):
        return getattr(self._graph, name)


def install_instrumentation():
    # Semantic gate (called from main.py's namespace)
    _patch(m, "semantic_precheck", "semantic_gate")

    if getattr(m, "scam_graph", None) is not None:
        m.scam_graph = _GraphProxy(m.scam_graph)

    try:
        import agents.langgraph_coordinator as lg
        import agents.url_agent as url_mod
        import agents.otp_agent as otp_mod
        import agents.contact_agent as contact_mod
    except Exception as exc:
        print(f"[latency] could not instrument agents: {exc}")
        return

    # Agent-level (looked up as globals by the LangGraph nodes at call time)
    _patch(lg, "analyze_otp", "agent.otp")
    _patch(lg, "analyze_url", "agent.url")
    _patch(lg, "analyze_contact", "agent.contact")

    # Sub-steps
    _patch(url_mod, "extract_url_and_brand", "url.extract_llm")
    _patch(url_mod, "get_redirect_chain", "url.redirects")
    _patch(url_mod, "get_domain_info", "url.whois")
    _patch(url_mod, "get_html_summary", "url.html_fetch+llm")
    _patch(url_mod, "get_brand_domain", "url.brand_lookup")
    _patch(url_mod, "run_cot_detection", "url.detection_llm")
    _patch(url_mod, "generate_short_explanation", "url.explanation_llm")
    _patch(otp_mod, "detect_otp_intent", "otp.intent_llm")
    _patch(contact_mod, "generate_contact_explanation", "contact.explanation_llm")


# ============================================================================
# REQUEST TIMING MIDDLEWARE
# ============================================================================

_ROWS = []  # summary rows kept in memory for the final report
_REQUEST_COUNTER = 0

CSV_FIELDS = [
    "time", "n", "sender", "http_status", "phone_to_server_ms", "total_backend_ms",
    "semantic_gate_ms", "langgraph_ms", "otp_agent_ms", "url_agent_ms",
    "contact_agent_ms", "fast_path", "breakdown_json",
]


def _ms(seconds):
    return round(seconds * 1000.0, 1)


def _write_csv(row):
    new_file = not CSV_PATH.exists()
    with CSV_PATH.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if new_file:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in CSV_FIELDS})


@m.app.middleware("http")
async def latency_middleware(request, call_next):
    global _REQUEST_COUNTER

    if request.method != "POST" or request.url.path != TARGET_PATH:
        return await call_next(request)

    recv_wall_ms = time.time() * 1000.0
    t_start = time.perf_counter()

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

    response = await call_next(request)
    t_end = time.perf_counter()

    with _EVENTS_LOCK:
        events = [e for e in _EVENTS if e[1] >= t_start and e[2] <= t_end + 0.05]
        _EVENTS.clear()

    _REQUEST_COUNTER += 1
    n = _REQUEST_COUNTER
    total_ms = _ms(t_end - t_start)

    # ---- phone -> server transit (approximate) ----
    transit_ms = None
    transit_note = ""
    if isinstance(phone_ts, (int, float)) and phone_ts > 0:
        transit_ms = round(recv_wall_ms - float(phone_ts), 1)
        if transit_ms < 0 or transit_ms > 60_000:
            transit_note = "  (unreliable: phone and PC clocks are not in sync)"

    # ---- stage aggregation ----
    events.sort(key=lambda e: e[1])
    durations = {}
    for stage, s, e in events:
        durations[stage] = durations.get(stage, 0.0) + (e - s)

    fast_path = "semantic_gate" in durations and "langgraph_total" not in durations

    # ---- print report ----
    line = "=" * 72
    print(f"\n{line}\nLATENCY REPORT  SMS #{n}   sender={sender}\n{line}")
    if transit_ms is not None:
        print(f"Phone -> server transit (approx) : {transit_ms:>9.1f} ms{transit_note}")
    print(f"{'Stage':<32}{'starts at':>12}{'duration':>14}")
    print("-" * 58)
    for stage, s, e in events:
        indent = "  " if "." in stage else ""
        print(f"{indent + stage:<32}{_ms(s - t_start):>9.1f} ms{_ms(e - s):>11.1f} ms")
    print("-" * 58)
    if fast_path:
        print("(Semantic fast-path: confirmed spam pattern, LangGraph skipped)")
    print(f"{'TOTAL BACKEND TIME':<32}{'':>12}{total_ms:>11.1f} ms  ({total_ms / 1000:.2f} s)")
    print("(Agents run in parallel, so their times overlap; TOTAL is the real time.)")

    row = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "n": n,
        "sender": sender,
        "http_status": response.status_code,
        "phone_to_server_ms": transit_ms if transit_ms is not None else "",
        "total_backend_ms": total_ms,
        "semantic_gate_ms": _ms(durations.get("semantic_gate", 0.0)),
        "langgraph_ms": _ms(durations.get("langgraph_total", 0.0)),
        "otp_agent_ms": _ms(durations.get("agent.otp", 0.0)),
        "url_agent_ms": _ms(durations.get("agent.url", 0.0)),
        "contact_agent_ms": _ms(durations.get("agent.contact", 0.0)),
        "fast_path": fast_path,
        "breakdown_json": json.dumps({k: _ms(v) for k, v in durations.items()}),
    }
    _ROWS.append(row)
    try:
        _write_csv(row)
    except Exception as exc:
        print(f"[latency] could not write CSV: {exc}")

    return response


# ============================================================================
# FINAL SUMMARY
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
    print(f"Average : {statistics.mean(totals):>10.1f} ms")
    print(f"Minimum : {min(totals):>10.1f} ms")
    print(f"Maximum : {max(totals):>10.1f} ms")
    print(f"Median  : {_percentile(totals, 50):>10.1f} ms")
    print(f"P95     : {_percentile(totals, 95):>10.1f} ms")

    for label, key in (
        ("Semantic gate avg", "semantic_gate_ms"),
        ("LangGraph avg", "langgraph_ms"),
        ("OTP agent avg", "otp_agent_ms"),
        ("URL agent avg", "url_agent_ms"),
        ("Contact agent avg", "contact_agent_ms"),
    ):
        vals = [r[key] for r in _ROWS if r[key]]
        if vals:
            print(f"{label:<19}: {statistics.mean(vals):>10.1f} ms  (over {len(vals)} SMS)")

    transits = [r["phone_to_server_ms"] for r in _ROWS
                if isinstance(r["phone_to_server_ms"], (int, float)) and 0 <= r["phone_to_server_ms"] <= 60_000]
    if transits:
        print(f"Phone->server avg  : {statistics.mean(transits):>10.1f} ms")

    print(f"\nPer-SMS details saved in: {CSV_PATH}")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    install_instrumentation()
    print(f"\n[latency] Backend starting on http://{HOST}:{PORT}")
    print("[latency] Send an SMS to the phone. Results appear here. Ctrl+C to stop.\n")
    try:
        uvicorn.run(m.app, host=HOST, port=PORT, log_level="info")
    finally:
        print_summary()