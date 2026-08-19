"""
url_agent.py

Context-augmented URL / SMS phishing detection agent.

Pipeline (mirrors the general structure of context-augmented, agentic
phishing detectors: extract -> collect context -> chain-of-thought
detection -> plain-language explanation):

    1. extract_url_and_brand()   - pull URL(s) and brand name(s) out of the SMS
    2. get_redirect_chain()      - follow shortened/redirected links to their final destination
    3. get_domain_info()         - WHOIS lookup on the final domain
    4. get_html_summary()        - fetch + summarize what the destination page actually is
    5. get_screenshot_summary()  - OPTIONAL: render + vision-analyze the page
    6. get_brand_domain()        - look up the brand's real official domain
    7. run_cot_detection()       - chain-of-thought phishing/spam/legit verdict
    8. generate_short_explanation() - turn the verdict into a 3-part plain-language message

Entry point: analyze_url(sms_text) -> dict, shaped to slot into main.py
the same way analyze_otp() does.

Dependencies:
    pip install requests python-whois beautifulsoup4 groq
    # optional, only needed if you turn on screenshots:
    pip install playwright
    playwright install chromium
"""

import re
import base64
import datetime
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

import requests
import whois  # python-whois


from utils.groq_client import groq_chat, groq_chat_json, groq_vision_chat, looks_truncated
from prompts.url_prompts import (
    EXTRACTION_PROMPT,
    DETECTION_PROMPT,
    EXPLANATION_PROMPT,
)


# ============================================================
# CONFIG
# ============================================================

REQUEST_TIMEOUT = 8            # seconds, per HTTP call
MAX_HTML_CHARS = 4000          # cap how much page text we send to the LLM
ENABLE_SCREENSHOT_ANALYSIS = False  # requires Playwright; off by default

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}


# ============================================================
# STEP 1: EXTRACTION
# ============================================================

def extract_url_and_brand(sms_text: str) -> Dict[str, Any]:
    """
    Uses the LLM to pull URLs and brand names out of the raw SMS text.
    Falls back to a regex URL scan if the LLM call fails, so a single
    flaky call doesn't kill the whole pipeline.
    """

    try:
        result = groq_chat_json(
            messages=[
                {
                    "role": "user",
                    "content": EXTRACTION_PROMPT.format(sms_text=sms_text),
                }
            ],
        )

        if "urls" in result:
            return result

    except Exception as e:
        print("extract_url_and_brand LLM call failed:", str(e))

    # Fallback: naive regex extraction
    urls = re.findall(r"https?://\S+", sms_text)

    return {
        "has_url": bool(urls),
        "urls": urls,
        "has_brand": False,
        "brands": [],
    }


# ============================================================
# STEP 2: REDIRECT CHAIN
# ============================================================

def get_redirect_chain(url: str) -> Dict[str, Any]:
    """
    Follows a URL through any redirects and returns the full chain plus
    the final destination. Shortened URLs are the norm in SMS, both
    legit and malicious, so we always need the real destination before
    we can reason about it.
    """

    chain = [url]
    final_url = url
    error = None

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        response.raise_for_status()

        chain = [r.url for r in response.history] + [response.url]
        final_url = response.url

    except requests.Timeout:
        error = f"Request timed out after {REQUEST_TIMEOUT} seconds"
    except requests.ConnectionError as e:
        error = f"Connection failed: {str(e)}"
    except requests.HTTPError as e:
        error = f"HTTP error: {str(e)}"
    except requests.RequestException as e:
        error = f"Request failed: {str(e)}"
    except Exception as e:
        error = f"Unexpected error following redirects: {str(e)}"

    return {
        "chain": chain,
        "final_url": final_url,
        "error": error,
    }


# ============================================================
# STEP 3: WHOIS / DOMAIN HISTORY
# ============================================================

def get_domain_info(final_url: str) -> Dict[str, Any]:
    """
    Looks up WHOIS registration info for the final destination domain.
    Recently-registered domains impersonating an established brand are
    a strong phishing signal; long-established domains are reassuring.
    """

    domain = urlparse(final_url).netloc

    if not domain:
        return {"domain": None, "error": "no_domain_found"}

    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age_days = None
        if isinstance(creation_date, datetime.datetime):
            # Some WHOIS servers return a timezone-aware creation_date.
            # datetime.now() is naive, so subtracting them directly raises
            # "can't subtract offset-naive and offset-aware datetimes".
            # Match now()'s awareness to creation_date's before subtracting.
            now = (
                datetime.datetime.now(creation_date.tzinfo)
                if creation_date.tzinfo
                else datetime.datetime.now()
            )
            age_days = (now - creation_date).days

        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(creation_date) if creation_date else None,
            "age_days": age_days,
            "error": None,
        }

    except requests.Timeout:
        return {
            "domain": domain,
            "error": f"WHOIS lookup timed out after {REQUEST_TIMEOUT} seconds",
        }
    except Exception as e:
        return {
            "domain": domain,
            "error": f"WHOIS lookup failed: {str(e)}",
        }


# ============================================================
# STEP 4: HTML CONTENT SUMMARY
# ============================================================

def _extract_visible_text(html: str) -> str:
    """Strips tags/scripts/styles down to plain visible text."""

    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "html.parser")

        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()

        text = soup.get_text(separator=" ", strip=True)

    except ImportError:
        # Fallback if bs4 isn't installed: crude tag stripping
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text).strip()

    return text[:MAX_HTML_CHARS]


def get_html_summary(final_url: str) -> str:
    """
    Fetches the destination page and asks the LLM to summarize what the
    site actually is (identity, purpose) so it can be compared against
    what the SMS claims.
    """

    try:
        response = requests.get(
            final_url,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        visible_text = _extract_visible_text(response.text)

        if not visible_text:
            return "Page returned no readable text content."

        try:
            summary = groq_chat(
                messages=[
                    {
                        "role": "user",
                        "content": (
                            "In 2-3 sentences, summarize what this webpage is "
                            "(what brand/company it claims to represent and "
                            "its apparent purpose), based only on this text:\n\n"
                            f"{visible_text}"
                        ),
                    }
                ],
                max_tokens=200,
            )
            return summary
        except Exception as e:
            return f"Could not summarize page content: {str(e)}"

    except requests.Timeout:
        return f"Page load timed out after {REQUEST_TIMEOUT} seconds"
    except requests.ConnectionError as e:
        return f"Could not connect to page: {str(e)}"
    except requests.HTTPError as e:
        return f"Page returned HTTP error: {str(e)}"
    except requests.RequestException as e:
        return f"Could not load page: {str(e)}"
    except Exception as e:
        return f"Unexpected error loading page: {str(e)}"


# ============================================================
# STEP 5 (OPTIONAL): SCREENSHOT + VISION ANALYSIS
# ============================================================

def get_screenshot_summary(final_url: str) -> str:
    """
    OPTIONAL step. Renders the page with Playwright and asks a
    vision-capable Groq model to describe logos/branding/layout.
    Disabled by default (ENABLE_SCREENSHOT_ANALYSIS=False) since it
    adds a heavy dependency and latency; the HTML summary alone covers
    most cases.
    """

    if not ENABLE_SCREENSHOT_ANALYSIS:
        return "Screenshot analysis disabled."

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(final_url, timeout=REQUEST_TIMEOUT * 1000)
            screenshot_bytes = page.screenshot(full_page=False)
            browser.close()

        image_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")

        return groq_vision_chat(
            prompt=(
                "Describe this webpage screenshot in 2-3 sentences: what "
                "brand/logo is visible, and what does the page appear to "
                "be for (login, payment, notification, etc.)?"
            ),
            image_base64=image_b64,
        )

    except Exception as e:
        return f"Screenshot analysis failed: {str(e)}"


# ============================================================
# STEP 6: BRAND'S TRUE DOMAIN
# ============================================================

def get_brand_domain(brand_name: str) -> Dict[str, Any]:
    """
    Looks up the brand's real official domain via a DuckDuckGo HTML
    search (no API key required, unlike Google's search API). This
    lets the detection step check whether the SMS's link actually
    points at the brand's own domain.
    """

    if not brand_name:
        return {"brand": None, "official_domain": None}

    try:
        response = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": brand_name},
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        # First external-looking link in the results is treated as the
        # brand's likely official site.
        links = re.findall(r'href="(https?://[^"]+)"', response.text)

        official_domain = None
        for link in links:
            domain = urlparse(link).netloc
            if domain and "duckduckgo.com" not in domain:
                official_domain = domain
                break

        return {
            "brand": brand_name,
            "official_domain": official_domain,
        }

    except requests.Timeout:
        return {
            "brand": brand_name,
            "official_domain": None,
            "error": f"Brand domain lookup timed out after {REQUEST_TIMEOUT} seconds",
        }
    except requests.RequestException as e:
        return {
            "brand": brand_name,
            "official_domain": None,
            "error": f"Brand domain lookup failed: {str(e)}",
        }
    except Exception as e:
        return {
            "brand": brand_name,
            "official_domain": None,
            "error": f"Unexpected error during brand lookup: {str(e)}",
        }


# ============================================================
# STEP 7: CHAIN-OF-THOUGHT DETECTION
# ============================================================

def run_cot_detection(
    sms_text: str,
    redirect_info: Dict[str, Any],
    domain_info: Dict[str, Any],
    html_summary: str,
    screenshot_summary: str,
    brand_domain: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Runs the chain-of-thought phishing/spam/legitimate classification,
    feeding in all the context gathered above.
    """

    try:
        prompt = DETECTION_PROMPT.format(
            sms_text=sms_text,
            redirect_chain=redirect_info.get("chain"),
            domain_info=domain_info,
            html_summary=html_summary,
            screenshot_summary=screenshot_summary,
            brand_domain=brand_domain.get("official_domain"),
        )

        result = groq_chat_json(
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=800,
        )

        # Ensure required fields exist
        if isinstance(result, dict):
            return result
        else:
            return {
                "category": "unknown",
                "is_malicious": False,
                "confidence": "low",
                "reasoning": "Detection model returned unexpected format",
                "brief_reason": "Unable to analyze",
            }

    except Exception as e:
        print(f"Detection failed: {str(e)}")
        return {
            "category": "unknown",
            "is_malicious": False,
            "confidence": "low",
            "reasoning": f"Analysis failed: {str(e)}",
            "brief_reason": "Unable to analyze message",
        }


# ============================================================
# STEP 8: SHORT EXPLANATION
# ============================================================

# ============================================================
# STEP 8: SHORT EXPLANATION  (patched v2)
# ============================================================
#
# Changes from v1 patch:
#   - logs the raw output of each attempt (even truncated ones) so you
#     can see what's actually happening instead of guessing
#   - if every attempt looks truncated, uses the LONGEST attempt instead
#     of the generic hardcoded fallback, as long as it clears a minimum
#     length - a slightly-imperfect real explanation beats a canned one
#   - only falls back to the hardcoded text if every attempt was empty
#     or too short to be useful (e.g. "**Decision:** This text is")

MIN_USABLE_EXPLANATION_LEN = 60  # chars; below this, treat as unusable


def generate_short_explanation(detection_result: Dict[str, Any]) -> str:
    """
    Converts the detailed verdict into a short, plain-language message
    for the end user (decision + why + what to do, <= 4 sentences).
    """

    prompt = EXPLANATION_PROMPT.format(
        category=detection_result.get("category", "unknown"),
        reasoning=detection_result.get("reasoning", "No reasoning provided."),
    )

    best_attempt = ""

    for max_tokens in (250, 400):
        try:
            explanation = groq_chat(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=max_tokens,
            )
            print(f"generate_short_explanation attempt (max_tokens={max_tokens}): {explanation!r}")

            if explanation and len(explanation) > len(best_attempt):
                best_attempt = explanation

            if explanation and not looks_truncated(explanation):
                return explanation
            # else: looked cut off or empty, try again with more headroom
        except Exception as e:
            print("generate_short_explanation call failed:", str(e))

    # Every attempt looked truncated (or failed). Prefer the longest real
    # attempt over the generic fallback, as long as it's long enough to
    # actually convey something - a slightly rough real answer beats a
    # canned one, but "**Decision:** This text is" should still fall
    # through to the hardcoded message below.
    if len(best_attempt) >= MIN_USABLE_EXPLANATION_LEN:
        return best_attempt

    category = detection_result.get("category", "unknown").lower()
    if category == "phishing":
        return "This message appears to be a potential scam. Do not click links or share information."
    elif category == "spam":
        return "This message appears to be spam. Consider deleting it and marking as spam."
    elif category == "legitimate":
        return "This message appears to be from a legitimate source. However, always verify before sharing sensitive info."
    else:
        return "Analysis encountered an error. Please review this message carefully before responding."
# ============================================================
# ORCHESTRATOR
# ============================================================

def analyze_url(sms_text: str) -> Dict[str, Any]:
    """
    Full pipeline entry point. Call this from main.py the same way
    analyze_otp() is called.

    Returns a dict shaped for the mobile app's SecurityCenter /
    scan-result screens:
        {
            "category": "legitimate" | "spam" | "phishing",
            "is_malicious": bool,
            "confidence": "low" | "medium" | "high",
            "brand_impersonated": str | None,
            "url": str | None,
            "short_explanation": str,
            "detailed_reasoning": str,
            "context": {...}   # raw context data, for a "view details" screen
        }
    """

    try:
        if not sms_text or not isinstance(sms_text, str):
            return {
                "category": "unknown",
                "is_malicious": False,
                "confidence": "low",
                "brand_impersonated": None,
                "url": None,
                "short_explanation": "Invalid message provided",
                "reasoning": "Message is empty or invalid",
                "context": {},
            }

        extraction = extract_url_and_brand(sms_text)

        urls = extraction.get("urls") or []
        brands = extraction.get("brands") or []

        # No URL -> skip the URL-specific context gathering, but still run
        # detection since brand impersonation / urgency can exist without a link.
        if not urls:
            detection = run_cot_detection(
                sms_text=sms_text,
                redirect_info={"chain": [], "final_url": None},
                domain_info={"domain": None},
                html_summary="No URL present in message.",
                screenshot_summary="No URL present in message.",
                brand_domain={"official_domain": None},
            )

            explanation = generate_short_explanation(detection)

            return {
                **detection,
                "short_explanation": explanation,
                "context": {"note": "no_url_in_message"},
            }

        url = urls[0]
        brand_name = brands[0] if brands else detection_brand_guess(sms_text)

        redirect_info = get_redirect_chain(url)
        final_url = redirect_info.get("final_url", url)

        domain_info = get_domain_info(final_url)
        html_summary = get_html_summary(final_url)
        screenshot_summary = get_screenshot_summary(final_url)
        brand_domain = get_brand_domain(brand_name)

        detection = run_cot_detection(
            sms_text=sms_text,
            redirect_info=redirect_info,
            domain_info=domain_info,
            html_summary=html_summary,
            screenshot_summary=screenshot_summary,
            brand_domain=brand_domain,
        )

        explanation = generate_short_explanation(detection)

        return {
            **detection,
            "short_explanation": explanation,
            "context": {
                "redirect_chain": redirect_info.get("chain", []),
                "final_url": final_url,
                "domain_info": domain_info,
                "html_summary": html_summary,
                "screenshot_summary": screenshot_summary,
                "brand_domain": brand_domain,
                "redirect_error": redirect_info.get("error"),
            },
        }

    except Exception as e:
        print(f"URL analysis error: {str(e)}")
        return {
            "category": "unknown",
            "is_malicious": False,
            "confidence": "low",
            "brand_impersonated": None,
            "url": None,
            "short_explanation": "Unable to analyze message",
            "reasoning": f"An error occurred during analysis: {str(e)}",
            "context": {"error": str(e)},
        }


def detection_brand_guess(sms_text: str) -> Optional[str]:
    """Tiny helper: returns None when extraction found no brand name at all."""
    return None