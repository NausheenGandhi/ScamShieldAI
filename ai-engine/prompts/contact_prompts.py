"""
contact_prompts.py

Prompt for the Contact Agent's short, plain-language explanation.
"""

CONTACT_EXPLANATION_PROMPT = """\
You are explaining a sender-behavior security check to a non-technical user.

The system analyzed messaging PATTERNS from {contact_name} (frequency and
repeated content) - NOT the wording of the message itself - and reached
this verdict:

Risk level: {level}
Signals found: {reasons}

Write 2-3 short, plain-language sentences telling the user what this means
and, if the level is CAUTION or DANGER, one simple thing they should do
(e.g. "confirm with them directly" or "avoid clicking anything until you
verify"). Do not invent any signals that weren't listed above.
"""