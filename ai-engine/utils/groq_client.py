"""
groq_client.py

Thin wrapper around the Groq Python SDK so the rest of the ai-engine
doesn't need to know about API keys, model names, or response parsing.

Setup:
    pip install groq
    export GROQ_API_KEY="your-key-here"

Groq's free tier is OpenAI-compatible, so this mirrors how the SmishX
paper calls ChatGPT-4o, just pointed at Groq-hosted open models instead
(e.g. Llama 3.3 70B) which is what makes the free tier usable.
"""

import os
import json
from typing import List, Dict, Optional

from groq import Groq


# ============================================================
# CONFIG
# ============================================================

# Text/reasoning model used for extraction, detection, explanation.
# Override with GROQ_TEXT_MODEL env var if Groq deprecates this one.
DEFAULT_TEXT_MODEL = os.environ.get("GROQ_TEXT_MODEL", "llama-3.3-70b-versatile")

# Vision-capable model, only needed if you enable screenshot analysis.
# Check https://console.groq.com/docs/models for the current vision model name.
DEFAULT_VISION_MODEL = os.environ.get("GROQ_VISION_MODEL", "llama-3.2-11b-vision-preview")

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

        _client = Groq(api_key=api_key)

    return _client


# ============================================================
# TEXT CHAT
# ============================================================

def groq_chat(
    messages: List[Dict[str, str]],
    model: str = DEFAULT_TEXT_MODEL,
    temperature: float = 0.2,
    max_tokens: int = 1500,
    json_mode: bool = False,
) -> str:
    """
    Calls Groq's chat completion endpoint and returns the text content.

    If json_mode=True, the model is asked to return a raw JSON object
    (equivalent to OpenAI's response_format={"type": "json_object"}).
    Your prompt MUST explicitly instruct the model to output JSON when
    using this, or Groq will reject the request.
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

    response = client.chat.completions.create(**kwargs)

    return response.choices[0].message.content


def groq_chat_json(
    messages: List[Dict[str, str]],
    model: str = DEFAULT_TEXT_MODEL,
    temperature: float = 0.2,
    max_tokens: int = 1500,
) -> dict:
    """
    Same as groq_chat(json_mode=True) but also parses the result.
    Falls back to a safe error dict if the model returns malformed JSON
    (small local models occasionally do this, unlike GPT-4o).
    """

    raw = groq_chat(
        messages=messages,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        json_mode=True,
    )

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {
            "error": "failed_to_parse_json",
            "raw_output": raw,
        }


# ============================================================
# VISION CHAT (optional, for screenshot analysis)
# ============================================================

def groq_vision_chat(
    prompt: str,
    image_base64: str,
    model: str = DEFAULT_VISION_MODEL,
    temperature: float = 0.2,
    max_tokens: int = 800,
) -> str:
    """
    Sends an image (base64, no data: prefix needed) + prompt to a
    vision-capable Groq model. Used for the optional screenshot
    analysis step in url_agent.py.
    """

    client = get_groq_client()

    response = client.chat.completions.create(
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

    return response.choices[0].message.content