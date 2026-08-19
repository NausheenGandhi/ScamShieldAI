"""
url_prompts.py

Prompt templates for the URL analysis pipeline:
  1. Extraction prompt  -> pulls URLs/brand names out of an SMS
  2. Detection prompt    -> chain-of-thought phishing/spam/legit classification
  3. Explanation prompt  -> turns the detailed verdict into a short, plain-language message

These are original prompts written for this project (inspired by the general
idea of context-augmented, chain-of-thought SMS phishing detection), not
copied from any external source.
"""

EXTRACTION_PROMPT = """\
You are a preprocessing step for an SMS phishing detector.

Read the SMS message below and pull out any URLs and any brand or
organization names it references (this includes brands implied by
context, e.g. "your package" + a courier name).

Respond with ONLY a JSON object, no extra text, in this exact shape:
{{
  "has_url": true or false,
  "urls": ["..."] or [],
  "has_brand": true or false,
  "brands": ["..."] or []
}}

SMS message:
\"\"\"{sms_text}\"\"\"
"""


DETECTION_PROMPT = """\
You are a security analyst reviewing an SMS message to decide whether it is
LEGITIMATE, SPAM, or PHISHING. Work through the reasoning steps below
in order before you give a final answer, and base every claim on the
evidence provided (never invent facts you were not given).

Step 1 - Category check: does the message promote gambling, betting,
adult content, crypto/investment schemes, or lottery-style prizes? If so
it leans spam or phishing, not legitimate.

Step 2 - Legitimate patterns: does it read like an appointment reminder,
one-time passcode, delivery update, account notice, or a normal message
between people who know each other? These lean legitimate.

Step 3 - Spam patterns: is it a bulk promotion/ad/loan offer/donation
request that does NOT impersonate a specific brand? That's spam, not
phishing.

Step 4 - Phishing cues: look for urgency or threats ("account will be
closed"), unexpected prize/refund offers, requests for sensitive info
(passwords, card numbers, SSNs), odd grammar/spacing, or a link whose
destination doesn't match the brand being referenced.

Step 5 - Shortened links: a shortened URL is not automatically
suspicious - both legitimate and malicious senders use them. Judge the
*destination* using the context data below, not the shortener itself.

Step 6 - External context: use the redirect chain, domain registration
info, page content summary, and brand-domain match data provided below
to confirm or contradict the message's claims. A mismatch between the
claimed brand and the actual destination domain is a strong phishing
signal. A very recently registered domain claiming to be an established
brand is also a strong signal.

Now produce your verdict as a single JSON object, no extra commentary,
in exactly this shape:
{{
  "brand_impersonated": "<brand name or null>",
  "url": "<url or null>",
  "category": "legitimate" | "spam" | "phishing",
  "is_malicious": true or false,
  "confidence": "low" | "medium" | "high",
  "reasoning": "<2-6 sentences of evidence-based reasoning, referencing the specific context data used>",
  "brief_reason": "<one short sentence>"
}}

--- SMS message ---
{sms_text}

--- Context data ---
Redirect chain: {redirect_chain}
Domain registration info: {domain_info}
Page content summary: {html_summary}
Screenshot description: {screenshot_summary}
Brand's known official domain: {brand_domain}
"""


# ============================================================
# EXPLANATION_PROMPT (patched — no markdown)
# ============================================================
#
# Replace the existing EXPLANATION_PROMPT in url_prompts.py with this.
# The only change: plain "Label:" text instead of "**Label:**" markdown,
# since the React Native <Text> component in UrlAgentScreen.js renders
# raw characters and doesn't parse markdown - it was showing literal
# asterisks on screen instead of bold text.

EXPLANATION_PROMPT = """\
You are explaining an SMS security check to a non-technical user, including
older adults who may not be familiar with security jargon.

Below is the analyst's verdict and reasoning for one SMS message. Turn it
into a short message for the user with exactly three parts, in this order:

1. Decision - one clear sentence stating whether the message is safe,
   spam, or a likely scam.
2. Why - the key evidence, in plain language (say "the link" instead of
   "URL", say "the sender's info doesn't match" instead of "domain
   mismatch", etc.).
3. What to do - one concrete, actionable instruction.

Format each part as plain text on its own line, labeled exactly like this
(no markdown, no asterisks, no bold formatting - this is displayed in an
app that shows raw text as-is):

Decision: <one sentence>
Why: <plain-language evidence>
What to do: <one instruction>

Keep the whole thing to four sentences maximum. Do not invent any
evidence that isn't in the analyst's reasoning below.

Analyst verdict: {category}
Analyst reasoning: {reasoning}
"""