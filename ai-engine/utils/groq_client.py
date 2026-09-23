"""
groq_client.py

Thin wrapper around the Groq Python SDK so the rest of the ai-engine
doesn't need to know about API keys, model names, or response parsing.

Setup:
    pip install groq
    export GROQ_API_KEY="your-key-here"

Groq's free tier is OpenAI-compatible, so this mirrors how the SmishX
paper calls ChatGPT-4o, just pointed at Groq-hosted open models instead.

NOTE ON MODELS (updated 2026-08):
Groq deprecated llama-3.3-70b-versatile and llama-3.1-8b-instant in
June 2026. Current defaults use the openai/gpt-oss family. If Groq
deprecates these too, override via env vars below rather than editing
code — check https://console.groq.com/docs/deprecations first.
"""

import os
import re
import json
import time
from typing import List, Dict, Optional
from dotenv import load_dotenv

load_dotenv()
from groq import Groq


# ============================================================
# CONFIG
# ============================================================

# Main text/reasoning model used for extraction, detection, explanation.
# These are JSON-mode / structured-output critical calls, so use the
# larger model for headroom on rate limits and output quality.
DEFAULT_TEXT_MODEL = os.environ.get("GROQ_TEXT_MODEL", "openai/gpt-oss-120b")

# Cheaper/faster model for non-critical summarization (e.g. html_summary).
# Separate from DEFAULT_TEXT_MODEL so a rate limit on summarization
# doesn't block detection/extraction, which share a TPM budget per model.
SUMMARY_MODEL = os.environ.get("GROQ_SUMMARY_MODEL", "openai/gpt-oss-20b")

# Vision-capable model, only needed if you enable screenshot analysis.
# Check https://console.groq.com/docs/models for the current vision model name.
DEFAULT_VISION_MODEL = os.environ.get("GROQ_VISION_MODEL", "meta-llama/llama-4-scout-17b-16e-instruct")

_client: Optional[Groq] = None


def get_groq_client() -> Groq:
    global _client

    if _client is None:
        api_key = os.environ.get("GROQ_API_KEY")

        if not api_key:
            raise RuntimeError(
                "GROQ_API_KEY environment variable is not set. "
                "Get a free key at https://console.groq.com/keys"
            )

        _client = Groq(
            api_key=api_key,
            timeout=10.0,
            max_retries=0,
        )

    return _client


# ============================================================
# RETRY HELPERS
# ============================================================

def _parse_retry_seconds(error_message: str, default: float = 2.0) -> float:
    """
    Groq's 429 errors include text like 'Please try again in 2.2125s'.
    Extract that so we wait exactly as long as needed, not a guess.
    """
    match = re.search(r"try again in ([\d.]+)s", error_message)
    if match:
        return float(match.group(1)) + 0.5  # small buffer
    return default


def _is_rate_limit_error(msg: str) -> bool:
    return "rate_limit_exceeded" in msg or "429" in msg


def _is_transient_json_error(msg: str) -> bool:
    # Empty/truncated generation under json_mode - usually recoverable
    # on retry, especially if it was caused by a rate-limit-adjacent
    # truncation rather than a genuinely bad prompt.
    return "json_validate_failed" in msg


def looks_truncated(text: str, min_prose_len: int = 20) -> bool:
    """
    Public wrapper around the truncation heuristic, for callers that use
    plain groq_chat() (not groq_chat_json) and need to check their own
    result - e.g. generate_short_explanation() in url_agent.py, whose
    output never passes through groq_chat_json's automatic flagging.
    """
    return _looks_truncated(text, min_prose_len=min_prose_len)


def _looks_truncated(text: str, min_prose_len: int = 20) -> bool:
    """
    Heuristic: a field that ends with a dangling markdown label like
    '**What to do:**' or stops mid-clause with no terminal punctuation
    is very likely a max_tokens cutoff, not an intentional short answer.

    Only applied to values long enough to be prose (min_prose_len), and
    only to values that actually look like prose (contain a space and
    aren't a URL) - so short enum-style fields like "phishing"/"high",
    brand names, and URLs (which never end in sentence punctuation by
    design) aren't flagged as false positives.
    """
    stripped = text.rstrip()
    if len(stripped) < min_prose_len:
        return False
    if " " not in stripped:
        return False
    if stripped.startswith(("http://", "https://")) or "://" in stripped:
        return False
    # Dangling label with nothing after it - catches both markdown-style
    # ("**What to do:**") and the plain-text style now used by
    # EXPLANATION_PROMPT ("What to do:") with no content following.
    if re.search(r"(\*\*[^*]+:\*\*|\b[A-Z][a-zA-Z ]{2,20}:)$", stripped):
        return True
    if stripped[-1] not in ".!?\"')]":
        return True
    return False


# ============================================================
# TEXT CHAT
# ============================================================

def groq_chat(
    messages: List[Dict[str, str]],
    model: str = DEFAULT_TEXT_MODEL,
    temperature: float = 0.2,
    max_tokens: int = 1500,
    json_mode: bool = False,
    max_retries: int = 2,
) -> str:
    """
    Calls Groq's chat completion endpoint and returns the text content.

    If json_mode=True, the model is asked to return a raw JSON object
    (equivalent to OpenAI's response_format={"type": "json_object"}).
    Your prompt MUST explicitly instruct the model to output JSON when
    using this, or Groq will reject the request.

    Retries on rate limits (honoring Groq's suggested wait time) and
    on transient JSON validation failures, up to max_retries times.
    """

    client = get_groq_client()

    kwargs = dict(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )

    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    last_err: Optional[Exception] = None

    for attempt in range(max_retries + 1):
        try:
            response = client.chat.completions.create(**kwargs)
            return response.choices[0].message.content
        except Exception as e:
            last_err = e
            msg = str(e)

            if _is_rate_limit_error(msg) and attempt < max_retries:
                wait = _parse_retry_seconds(msg)
                time.sleep(wait)
                continue

            if _is_transient_json_error(msg) and attempt < max_retries:
                time.sleep(1.0)
                continue

            raise

    # Should be unreachable, but keep type checkers happy.
    raise last_err


def groq_chat_json(
    messages: List[Dict[str, str]],
    model: str = DEFAULT_TEXT_MODEL,
    temperature: float = 0.2,
    max_tokens: int = 1500,
) -> dict:
    """
    Same as groq_chat(json_mode=True) but also parses the result.
    Falls back to a safe error dict if the model returns malformed JSON
    (small local models occasionally do this, unlike GPT-4o), or if
    the API call itself fails after retries are exhausted.

    Also flags any string field whose value looks like it was cut off
    mid-sentence by hitting max_tokens (e.g. ends in a dangling
    "**What to do:**" with nothing after it). Parsed JSON can still be
    structurally valid even when a value inside it was truncated, so
    this can't be caught by json.loads() alone. Flagged field names are
    added to "_truncated_fields" so callers can fall back to a
    shorter/safer field (e.g. brief_reason) instead of showing broken
    text to the user.
    """

    try:
        raw = groq_chat(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=True,
        )
    except Exception as e:
        return {
            "error": "groq_call_failed",
            "raw_output": str(e),
        }

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {
            "error": "failed_to_parse_json",
            "raw_output": raw,
        }

    truncated_fields = [
        key
        for key, value in parsed.items()  # snapshot before mutating parsed below
        if isinstance(value, str) and _looks_truncated(value)
    ]
    if truncated_fields:
        parsed["_truncated_fields"] = truncated_fields

    return parsed


# ============================================================
# VISION CHAT (optional, for screenshot analysis)
# ============================================================

def groq_vision_chat(
    prompt: str,
    image_base64: str,
    model: str = DEFAULT_VISION_MODEL,
    temperature: float = 0.2,
    max_tokens: int = 800,
    max_retries: int = 2,
) -> str:
    """
    Sends an image (base64, no data: prefix needed) + prompt to a
    vision-capable Groq model. Used for the optional screenshot
    analysis step in url_agent.py.
    """

    client = get_groq_client()

    kwargs = dict(
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{image_base64}"
                        },
                    },
                ],
            }
        ],
    )

    last_err: Optional[Exception] = None

    for attempt in range(max_retries + 1):
        try:
            response = client.chat.completions.create(**kwargs)
            return response.choices[0].message.content
        except Exception as e:
            last_err = e
            msg = str(e)
            if _is_rate_limit_error(msg) and attempt < max_retries:
                time.sleep(_parse_retry_seconds(msg))
                continue
            raise

    raise last_err