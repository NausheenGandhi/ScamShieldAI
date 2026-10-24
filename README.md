# ScamShield AI

ScamShield AI is a real-time SMS scam detection system for Android. It combines an on-device SMS monitor, a FastAPI backend, and a multi-agent analysis engine. Each incoming message is examined from several independent angles (sender identity, embedded links, OTP intent, sender behaviour, and similarity to known spam campaigns). The findings are merged into one risk score with a plain-language explanation.

The system is designed around three principles:

- **Explainability.** Every verdict is backed by named signals and human-readable reasons, not an opaque score.
- **Graceful degradation.** If MongoDB, the LLM provider, or optional ML libraries are unavailable, each component falls back to a safe default instead of failing the request.
- **Privacy.** OTP codes are stripped locally before any LLM call, and message bodies are hashed rather than stored by default.

---

## Table of contents

1. [Architecture](#architecture)
2. [Analysis agents](#analysis-agents)
3. [Semantic spam gate](#semantic-spam-gate)
4. [Score aggregation](#score-aggregation)
5. [Tamper-evident storage](#tamper-evident-storage)
6. [Repository layout](#repository-layout)
7. [Prerequisites](#prerequisites)
8. [Configuration](#configuration)
9. [Running the backend](#running-the-backend)
10. [Running the mobile app](#running-the-mobile-app)
11. [API reference](#api-reference)
12. [Testing and evaluation](#testing-and-evaluation)
13. [Privacy and security notes](#privacy-and-security-notes)
14. [Known limitations](#known-limitations)

---

## Architecture

```
Android device
  SmsReceiver.kt  (BroadcastReceiver)
    - reads sender and body
    - looks up saved contact
    - collects device context (foreground app, screen lock state)
        |
        |  POST /analyze-sms   (adb reverse tcp:8000 tcp:8000)
        v
FastAPI backend (backend/app/main.py)
  1. Semantic spam gate
       embed message -> compare with known spam patterns in MongoDB
       confirmed spam pattern?  -> return SPAM immediately (fast path)
  2. LangGraph coordinator
       detect components -> route in parallel:
         OTP agent      (if a 4-8 digit code is present)
         URL agent      (if a link or domain is present)
         Contact agent  (always)
       -> aggregate results -> final risk score and status
        |
        v
Response saved to Android SharedPreferences
        |
        v
React Native (Expo) UI polls the native module and renders results
```

Technology summary:

| Layer | Technology |
|---|---|
| Mobile client | React Native (Expo), Kotlin native module for SMS receiving |
| API | FastAPI, Uvicorn |
| Orchestration | LangGraph (parallel fan-out with a single aggregator node) |
| LLM provider | Groq (OpenAI-compatible models, configurable) |
| Embeddings | sentence-transformers, `all-MiniLM-L6-v2` by default |
| Anomaly detection | scikit-learn IsolationForest (Pattern agent) |
| Persistence | MongoDB Atlas via PyMongo |

---

## Analysis agents

### OTP agent

Determines whether a message contains a one-time code and what the message is trying to do with it.

- Detects OTP-like codes locally (`\b\d{4,8}\b`) and replaces them with `[OTP]` before anything reaches the LLM. The code is never returned, logged, or stored.
- Uses an LLM only for intent classification into one of: `NORMAL_OTP`, `OTP_SHARING_REQUEST`, `UNREQUESTED_OTP`, `OTP_PHISHING`, `OTP_THREAT`, `OTP_CUSTOMER_CARE_SCAM`, `NON_OTP`.
- A deterministic risk engine (`risk_engine.py`) converts intent plus device context into a score. Context includes whether the OTP was expected (based on the foreground app), whether the sender is a plain mobile number, whether a link is present, and whether the screen was locked.
- Output level: `SAFE`, `CAUTION`, `DANGER`, or `NOT_OTP`.

### URL agent

Analyzes links in the message with a context-augmented, chain-of-thought pipeline:

1. Extract URLs (regex, cross-checked with an LLM) and referenced brands.
2. Follow redirects to the final destination.
3. WHOIS lookup for domain age and registrar.
4. Fetch and summarize the destination page.
5. Optional screenshot analysis with a vision model (disabled by default, requires Playwright).
6. Look up the brand's official domain.
7. LLM verdict: `legitimate`, `spam`, or `phishing`, with confidence.
8. Short plain-language explanation for end users.

A message with no URL short-circuits with zero network or LLM calls. All fetches pass an SSRF guard that rejects loopback, private, link-local, and reserved addresses, including after redirects.

### Contact agent

Fully offline and low latency, apart from an optional explanation call. It combines:

- **Sender classification** (`sender_classifier.py`): personal number, business number, alphanumeric sender ID, short code, suspicious, or unknown. Uses the `phonenumbers` library with India as the default region.
- **Message risk signals** (`risk_analyzer.py`): regex-based detection of financial requests, credential requests, urgency, threats, secrecy requests, personal-information requests, prize scams, delivery-fee scams, and links (including URL shorteners).
- **Message classification**: `NORMAL`, `SUSPICIOUS`, `SPAM`, or `SCAM`. Uses a trained scikit-learn model if one exists at `CONTACT_MODEL_PATH`; otherwise a transparent weighted rule-based scorer with combination bonuses for known scam templates. No trained model is shipped.
- **Impersonation detection** (`impersonation.py`): checks whether a message claims to be from a known organization (banks, payment apps, couriers, government bodies) while the sender ID does not match. Takes into account that Indian transactional SMS must use registered alphanumeric headers.
- **Sender reputation** (`reputation.py`): per-sender counters stored in MongoDB and converted to a 0-100 reputation score.
- **Trust score** (`trust_score.py`): a weighted 0-100 score with a verdict (`TRUSTED`, `LOW_RISK`, `CAUTION`, `SUSPICIOUS`, `HIGH_RISK`). A danger cap prevents a trusted sender or saved contact from masking clearly dangerous message content.

### Pattern agent

Analyzes sender behaviour over time: message frequency in 5-minute, 15-minute, 1-hour and 24-hour windows, bursts, near-duplicate content (SequenceMatcher similarity), repeated URLs, unusually regular timing, and sudden volume changes. An IsolationForest anomaly score is added when enough history exists. It is exposed through `POST /analyze-pattern` and displayed in the Contact Agent screen. It is not currently part of the LangGraph routing.

### Coordinator

`agents/langgraph_coordinator.py` routes each SMS to the relevant agents in parallel and aggregates their results. A separate weighted combiner exists in `agents/coordinator.py` (`combine_agent_results`) that also includes the Pattern agent; it is covered by tests but the production graph uses the aggregator described below.

---

## Semantic spam gate

Before any agent runs, `semantic_precheck` embeds the message (after stripping URLs, bare domains, and greeting boilerplate) and compares it against stored spam patterns using cosine similarity.

- Default similarity threshold: `0.70` (`SEMANTIC_SIMILARITY_THRESHOLD`). A token-overlap rescue applies just below the threshold.
- Each match is recorded as an append-only event. A pattern becomes `CONFIRMED_SPAM` when it reaches `SPAM_OCCURRENCE_THRESHOLD` occurrences (default `5`) or is explicitly confirmed.
- Messages matching a confirmed pattern return immediately with status `SPAM`, skipping the LangGraph pipeline.
- New, unmatched messages create a new pending pattern.

This means common campaigns are recognized across all users of the deployment at embedding-lookup cost, without LLM calls.

---

## Score aggregation

For messages that reach LangGraph, the aggregator collects each participating agent's risk score:

- OTP agent: its risk score.
- URL agent: its risk score (`score`, falling back to `risk_score`).
- Contact agent: `100 - trust score`.

The per-agent risk scores are summed and clamped to the range 0-100. `safe_score` is `100 - risk_score`. The confidence score is the mean of agent confidences.

| Risk score | Status |
|---|---|
| 85 and above | `CRITICAL` |
| 65 to 84 | `HIGH` |
| 35 to 64 | `MEDIUM` |
| 15 to 34 | `LOW` |
| below 15 | `SAFE` |

The evaluation harness treats a risk score of 35 or higher as "predicted scam" by default (`--threshold`).

---

## Tamper-evident storage

Records for message history, spam patterns, pattern events, and audit logs are written through a security gateway (`backend/app/database/repository.py`):

- **Authentication and authorization.** Callers authenticate with per-actor secrets (`ACTOR_SECRET_<ACTOR>`). Operations are checked against an allow-list per actor and per resource. Update and delete operations are blocked outright.
- **Input validation.** Only whitelisted fields are accepted. Server-generated fields (IDs, hashes, timestamps, sequence numbers, status, counts) cannot be supplied by the caller.
- **Hash chain.** Each record includes `previous_hash` and an HMAC-SHA256 `integrity_hash` computed with `INTEGRITY_HMAC_KEY`, which lives outside the database. A unique index on `chain_seq` prevents forks; concurrent writers retry.
- **Append-only patterns.** Pattern counts and status are derived from events, never updated in place.
- **Audit trail.** Successful operations and denied attempts are logged to a chained audit collection.

The chain detects edits, deletions, and forged continuations without the HMAC key. It does not protect against full database rollback to an earlier snapshot, compromise of the HMAC key, or an administrator bypassing the restricted application role.

---

## Repository layout

The exact top-level folder names may differ slightly in your checkout; this reflects the structure the code expects.

```
project-root/
  backend/
    app/
      main.py                      FastAPI application and endpoints
      .env                         Environment variables (not committed)
      database/
        mongodb.py                 MongoDB client, collections, indexes
        repository.py              Secure, hash-chained write gateway
      security/
        access_control.py          Authentication, authorization, validation
        hashing.py                 Canonical JSON, SHA-256, HMAC-SHA256
        integrity.py               Hash chain build and verification
      services/
        embedding_service.py       Sentence-transformer embeddings
        semantic_spam_service.py   Semantic gate and pattern lifecycle
    scripts/                       check_atlas.py, test_tamper_proof_full.py
    evaluate_*.py, measure_*.py    Evaluation and latency tooling
  ai-engine/
    agents/
      otp_agent.py
      url_agent.py
      contact_agent.py
      contact/                     Sender, risk, impersonation, trust, reputation
      pattern_agent.py
      pattern/                     Features, history, model
      coordinator.py
      langgraph_coordinator.py
    prompts/                       LLM prompt templates
    utils/groq_client.py           Groq wrapper with retry and JSON handling
    risk_engine.py                 OTP risk scoring
  mobile/
    App.js
    components/                    Screens (Security Center, agents, scan)
    constants/                     API base URL, colors
    plugins/withSmsNative          Expo config plugin for the native module
    android/ (generated)           SmsReceiver.kt, SmsNativeModule.kt
```

---

## Prerequisites

- Python 3.11 or newer
- Node.js and the Expo toolchain (the Expo documentation for the SDK version in use applies; see `AGENTS.md`)
- Android device or emulator, plus Android Debug Bridge (`adb`)
- A Groq API key
- A MongoDB Atlas cluster (optional but recommended; see "Graceful degradation" below)

---

## Configuration

Create `backend/app/.env` (loaded by the backend and by the test scripts):

```
# LLM provider
GROQ_API_KEY=your-groq-key
# Optional model overrides
# GROQ_TEXT_MODEL=openai/gpt-oss-120b
# GROQ_SUMMARY_MODEL=openai/gpt-oss-20b
# GROQ_VISION_MODEL=meta-llama/llama-4-scout-17b-16e-instruct

# Database
MONGODB_URI=mongodb+srv://...
MONGODB_DATABASE=scamshield

# Tamper-evident storage
INTEGRITY_HMAC_KEY=a-long-random-secret
ACTOR_SECRET_APPLICATION_SERVICE=another-long-random-secret
# ACTOR_SECRET_ADMINISTRATOR=...
# ACTOR_SECRET_AUDIT_SECURITY_SERVICE=...

# Semantic gate tuning
# SEMANTIC_SIMILARITY_THRESHOLD=0.70
# SPAM_OCCURRENCE_THRESHOLD=5
# EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2

# Contact agent
# CONTACT_MODEL_PATH=models/contact_message_classifier.joblib
# STORE_RAW_MESSAGE_BODY=false
```

Graceful degradation behaviour:

| Missing | Effect |
|---|---|
| `MONGODB_URI` | Sender reputation and message history are disabled; agents use neutral defaults. Semantic pattern persistence is unavailable. |
| `ACTOR_SECRET_APPLICATION_SERVICE` or `INTEGRITY_HMAC_KEY` | Database writes through the security gateway are rejected (and logged); requests still complete. |
| `sentence-transformers` | A hash-based stand-in embedding is used. It is not semantic, so similarity results are not meaningful. |
| Trained contact classifier | Rule-based classification is used. |
| `GROQ_API_KEY` | LLM-dependent steps fall back to safe defaults or fail the specific agent. |

---

## Running the backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install sentence-transformers   # needed for real semantic embeddings
```

`sentence-transformers` is not listed in `requirements.txt`; install it explicitly for meaningful semantic matching.

Start the server:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Verify:

```bash
curl http://127.0.0.1:8000/health
```

On startup the backend loads the embedding model and ensures MongoDB indexes exist. Index creation requires a MongoDB user with index privileges.

---

## Running the mobile app

The SMS receiver is a native Kotlin component, so the app must run as a development build (or release build), not in Expo Go.

1. Install dependencies: `npm install`
2. Generate and run the Android project: `npx expo run:android`
3. Grant the permissions the app requests: SMS (read and receive), Contacts, and Notifications.
4. Point the device at the backend. `SmsReceiver.kt` posts to `http://localhost:8000`, so forward the port:

   ```bash
   adb reverse tcp:8000 tcp:8000
   ```

   The React Native screens use `API_BASE_URL` in `constants/api.js`. Choose the value for your setup:

   | Environment | Value |
   |---|---|
   | iOS Simulator | `http://127.0.0.1:8000` |
   | Android emulator | `http://10.0.2.2:8000` |
   | Physical device on the same network | `http://<computer-LAN-IP>:8000` |

5. Send an SMS to the device. The result appears in the Security Center and agent screens.

---

## API reference

All request bodies share one schema (`SMSRequest`):

| Field | Type | Notes |
|---|---|---|
| `sender` | string | Required |
| `body` | string | Required; empty or whitespace returns HTTP 400 |
| `timestamp` | integer | Epoch milliseconds, optional |
| `source` | string | Optional |
| `expected_otp` | boolean | Default `false` |
| `foreground_app` | string | Default empty |
| `screen_unlocked` | boolean | Default `true` |
| `is_saved_contact` | boolean | Default `false` |
| `contact_name` | string | Optional |

| Method and path | Purpose |
|---|---|
| `GET /` | Service status and agent availability |
| `GET /health` | Health check with per-agent flags |
| `POST /analyze-sms` | Full pipeline: semantic gate, then LangGraph. Returns `analysis`, `routes`, and per-agent `agents` results. |
| `POST /analyze-url` | URL agent only |
| `POST /analyze-contact` | Contact agent only |
| `POST /analyze-pattern` | Pattern agent only |

Example:

```bash
curl -X POST http://127.0.0.1:8000/analyze-sms \
  -H "Content-Type: application/json" \
  -d '{
        "sender": "+919876500001",
        "body": "URGENT: Your account will be blocked. Send OTP now.",
        "is_saved_contact": false
      }'
```

Abridged response:

```json
{
  "success": true,
  "sms": { "sender": "...", "body": "...", "timestamp": null },
  "analysis": {
    "status": "HIGH",
    "score": 72,
    "risk_score": 72,
    "safe_score": 28,
    "confidence_score": 80,
    "reasons": ["..."],
    "agent_results": { "otp": {}, "url": null, "contact": {} }
  },
  "routes": ["otp", "contact"],
  "agents": []
}
```

A semantic fast-path hit returns `analysis.status = "SPAM"`, `processing_path = "SEMANTIC_FAST_PATH"`, a `reason`, and a `report_count`.

---

## Testing and evaluation

Most scripts are run from the `backend/` or `ai-engine/` directory with the environment configured.

| Script | Type | Needs |
|---|---|---|
| `test_security_layer.py` (tests folder) | Unit tests for hash chain, access control, validation, patterns | No database (in-memory fake) |
| `test_semantic_integration.py` | End-to-end semantic gate against fake collections | No database |
| `test_pattern_agent.py` | Unit tests for the Pattern agent and coordinator | Optional |
| `test_contact_agent.py` | Manual smoke test | Optional MongoDB |
| `test_contact_agent_blackbox.py` | HTTP contract tests for `/analyze-contact` | Running backend |
| `test_otp_agent_blackbox.py` | HTTP contract tests (pytest) | Running backend, Groq |
| `url_agent_blackbox_test.py` | URL agent black-box suite | Running backend, Groq |
| `otp_agent_blackbox_test.py` | OTP agent black-box suite | Running backend, Groq |
| `scripts/check_atlas.py` | Verifies indexes and hash chain on a real Atlas database | Atlas, database name containing "test" |
| `scripts/test_tamper_proof_full.py` | Update, delete, forgery, and race tests on real Atlas | Atlas, database name containing "test" |
| `evaluate_precision_recall.py` | Precision, recall, F1, MCC, ROC-AUC, threshold sweep over a labeled SMS set | Running backend |
| `evaluate_embedding_quality.py` | Embedding separation, threshold sweep, retrieval accuracy | Real embedding model |
| `plot_family_heatmap.py` | Heatmap from the embedding similarity CSV | matplotlib |
| `measure_latency.py`, `measure_pipeline_stepwise.py`, `measure_fastpath_latency.py` | Instrumented server runs that log per-stage latency to CSV | Run instead of `uvicorn` |

Examples:

```bash
# Unit tests (no external services)
python -m unittest discover -s tests -v

# Full-pipeline evaluation against a running backend
python evaluate_precision_recall.py --repeat 3 --delay 0.5

# Embedding quality
python evaluate_embedding_quality.py
```

Evaluation notes:

- Results depend on LLM behaviour and on the state of the semantic pattern store. Clear `spam_patterns` and `pattern_events` before an evaluation run if you want first-time (non-fast-path) measurements.
- The tamper-resistance scripts deliberately corrupt data and refuse to run unless `MONGODB_DATABASE` contains `test`.

---

## Privacy and security notes

- OTP codes are replaced with `[OTP]` before LLM calls and are never returned, stored, or logged by the agent. The API response reports this under `privacy`.
- Message bodies are stored only as SHA-256 hashes by default in the message analysis history. Set `STORE_RAW_MESSAGE_BODY=true` only for local debugging.
- The URL agent refuses to fetch private or internal addresses.
- The URL agent sends the original SMS to the backend, which in turn sends content to the Groq API for analysis. Deployments should consider this when assessing data-handling requirements.
- CORS is currently configured with `allow_origins=["*"]`. Restrict it before any production deployment.
- The backend has no end-user authentication on its analysis endpoints. Place it behind appropriate network controls or add authentication before exposing it publicly.
- Never commit `.env` files, HMAC keys, or actor secrets.

---

## Known limitations

- Android only. SMS receiving relies on a native Android broadcast receiver.
- Impersonation detection covers a fixed registry of organizations in `impersonation.py`. Extend `IMPERSONATED_ENTITIES` for additional brands.
- Without `sentence-transformers` installed, semantic matching uses a non-semantic fallback.
- WHOIS and brand-domain lookups are best-effort and may fail or return incomplete data.