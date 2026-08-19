"""
url_agent.py

Context-augmented URL / SMS phishing detection agent.

Pipeline:
    1. extract_url_and_brand()   - pull URL(s) and brand name(s) out of the SMS
    2. get_redirect_chain()      - follow shortened/redirected links to their final destination
    3. get_domain_info()         - WHOIS lookup on the final domain
    4. get_html_summary()        - fetch + summarize what the destination page actually is
    5. get_screenshot_summary()  - OPTIONAL: render + vision-analyze the page
    6. get_brand_domain()        - look up the brand's real official domain
    7. run_cot_detection()       - chain-of-thought phishing/spam/legit verdict
    8. generate_short_explanation() - turn the verdict into a 3-part plain-language message

If the message has no URL at all, none of the above runs - analyze_url()
returns a fast "no_url" result instead, since this agent's job is
specifically link analysis (scam-pattern-without-a-link detection lives
in pattern_agent.py).

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
import socket
import ipaddress
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

# Regex used both to detect "is there a URL at all" (fast path, before
# any LLM call) and as the extraction fallback. This is the one place
# that decides whether the rest of the pipeline runs, so it needs to be
# reliable on its own, not dependent on the LLM.
URL_REGEX = re.compile(r"https?://\S+")

# Punctuation that regex URL matching commonly drags in from the
# surrounding sentence (e.g. "check http://bit.ly/x." or "...link,")
URL_TRAILING_PUNCT = ").,!?;:'\""


# ============================================================
# URL VALIDATION / SSRF GUARD
# ============================================================

def _clean_url(url: str) -> str:
    """Strips trailing sentence punctuation a regex match can pick up."""
    return url.rstrip(URL_TRAILING_PUNCT)


def _is_valid_url_format(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def _is_safe_public_host(hostname: Optional[str]) -> bool:
    """
    Returns False for hostnames that resolve to loopback, private,
    link-local, reserved, or unspecified addresses - or that fail to
    resolve at all. An SMS URL is attacker-controlled input, so before
    this backend fetches it we need to make sure it can't be pointed at
    localhost, an internal service, or cloud metadata endpoints like
    169.254.169.254.
    """

    if not hostname:
        return False

    host = hostname.lower().strip(".")

    if host in ("localhost",) or host.endswith(".local"):
        return False

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    except Exception:
        return False

    if not infos:
        return False

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False

    return True


def _is_safe_url(url: str) -> bool:
    if not _is_valid_url_format(url):
        return False
    return _is_safe_public_host(urlparse(url).hostname)


def _extract_urls_regex(sms_text: str) -> List[str]:
    return [_clean_url(u) for u in URL_REGEX.findall(sms_text)]


# ============================================================
# STEP 1: EXTRACTION
# ============================================================

def extract_url_and_brand(sms_text: str) -> Dict[str, Any]:
    """
    Uses the LLM to pull brand names out of the raw SMS text, and to
    double-check the URL list. The URL list itself is not trusted from
    the LLM alone though - see analyze_url(), which always cross-checks
    against a regex scan, since the "does this message have a URL"
    decision needs to be reliable even if the LLM call fails or
    hallucinates.
    """

    regex_urls = _extract_urls_regex(sms_text)

    try:
        result = groq_chat_json(
            messages=[
                {
                    "role": "user",
                    "content": EXTRACTION_PROMPT.format(sms_text=sms_text),
                }
            ],
        )

        if isinstance(result, dict) and "urls" in result:
            llm_urls = [_clean_url(u) for u in (result.get("urls") or [])]
            # Union, regex first: catches anything the LLM missed, while
            # still keeping any extra URL the LLM found.
            merged = list(dict.fromkeys(regex_urls + llm_urls))
            result["urls"] = merged
            result["has_url"] = bool(merged)
            return result

    except Exception as e:
        print("extract_url_and_brand LLM call failed:", str(e))

    # Fallback: regex only
    return {
        "has_url": bool(regex_urls),
        "urls": regex_urls,
        "has_brand": False,
        "brands": [],
    }


# ============================================================
# STEP 2: REDIRECT CHAIN
# ============================================================

def get_redirect_chain(url: str) -> Dict[str, Any]:
    """
    Follows a URL through any redirects and returns the full chain plus
    the final destination. Refuses to fetch (and refuses to follow into)
    private/internal addresses - see _is_safe_url().
    """

    if not _is_safe_url(url):
        return {
            "chain": [url],
            "final_url": url,
            "error": "blocked_unsafe_url",
        }

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

        # A redirect can land somewhere unsafe even if the original URL
        # was fine - re-check the actual destination before it's used
        # for WHOIS / HTML fetching downstream.
        if not _is_safe_url(final_url):
            return {
                "chain": chain,
                "final_url": final_url,
                "error": "blocked_unsafe_redirect_destination",
            }

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
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text).strip()

    return text[:MAX_HTML_CHARS]


def get_html_summary(final_url: str) -> str:
    """
    Fetches the destination page and asks the LLM to summarize what the
    site actually is, so it can be compared against what the SMS claims.
    Refuses to fetch unsafe (internal/private) destinations.
    """

    if not _is_safe_url(final_url):
        return "Blocked: destination resolves to a private or internal address."

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
    Disabled by default; also respects the safe-URL check.
    """

    if not ENABLE_SCREENSHOT_ANALYSIS:
        return "Screenshot analysis disabled."

    if not _is_safe_url(final_url):
        return "Blocked: destination resolves to a private or internal address."

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
    search, so the detection step can check whether the SMS's link
    actually points at the brand's own domain.
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
        except Exception as e:
            print("generate_short_explanation call failed:", str(e))

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
# NO-URL FAST PATH
# ============================================================

def _no_url_result(note: str) -> Dict[str, Any]:
    """
    Returned immediately, with zero LLM/network calls, when the message
    has no URL. This agent's job is link analysis specifically - a
    scam message with no link at all is out of scope here (that's what
    pattern_agent.py is for), so there's nothing to gain from running
    the full detection pipeline on it.
    """
    return {
        "category": "no_url",
        "is_malicious": False,
        "confidence": "high",
        "brand_impersonated": None,
        "url": None,
        "short_explanation": "This message doesn't contain a link, so there's nothing for the URL check to analyze.",
        "reasoning": "No URL was found in the message.",
        "brief_reason": "No link in message.",
        "context": {"note": note},
    }


# ============================================================
# ORCHESTRATOR
# ============================================================

def analyze_url(sms_text: str) -> Dict[str, Any]:
    """
    Full pipeline entry point. Call this from main.py the same way
    analyze_otp() is called.

    Behavior: if sms_text contains no URL, returns _no_url_result()
    immediately - no LLM calls, no outbound requests. Only messages
    that actually contain a link go through extraction, redirect
    following, WHOIS, page summarization, and chain-of-thought
    detection.

    Returns a dict shaped for the mobile app's SecurityCenter /
    scan-result screens:
        {
            "category": "legitimate" | "spam" | "phishing" | "no_url" | "unknown",
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
        if not sms_text or not isinstance(sms_text, str) or not sms_text.strip():
            return _no_url_result("empty_message")

        # Fast, deterministic check FIRST - before any LLM call. This is
        # the gate: no URL, no analysis.
        if not URL_REGEX.search(sms_text):
            return _no_url_result("no_url_in_message")

        extraction = extract_url_and_brand(sms_text)
        urls = extraction.get("urls") or []
        brands = extraction.get("brands") or []

        if not urls:
            # Regex found something the extraction step then filtered out
            # entirely (rare) - fall back to the raw regex match directly
            # rather than silently skipping a message that does have a URL.
            urls = _extract_urls_regex(sms_text)

        if not urls:
            return _no_url_result("no_url_in_message")

        # Prefer the first URL with a valid http(s)://host shape.
        url = next((u for u in urls if _is_valid_url_format(u)), None)
        if not url:
            return _no_url_result("no_valid_url_found")

        brand_name = brands[0] if brands else None

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
            "url": detection.get("url") or url,
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