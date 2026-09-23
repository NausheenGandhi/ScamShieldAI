from __future__ import annotations

import operator
import re

from typing import TypedDict, Annotated

from langgraph.graph import StateGraph, START, END
from langgraph.types import Send

from .otp_agent import analyze_otp
from .url_agent import analyze_url
from .contact_agent import analyze_contact


CONTACT_AGENT = "CONTACT"


# ============================================================
# SCORE HELPERS
# ============================================================

def _bounded_score(value: object) -> float | None:
    """
    Return a valid score between 0 and 100.
    Booleans are not treated as numbers.
    """

    if isinstance(value, bool):
        return None

    if not isinstance(value, (int, float)):
        return None

    return max(
        0.0,
        min(100.0, float(value))
    )


def _confidence_score(value: object) -> float | None:
    """
    Convert confidence values into a 0-100 numeric score.
    """

    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):

        return max(
            0.0,
            min(100.0, float(value))
        )

    if isinstance(value, str):

        return {
            "high": 90.0,
            "medium": 70.0,
            "low": 50.0,
        }.get(
            value.strip().lower()
        )

    return None


# ============================================================
# AGGREGATOR
# ============================================================

def aggregate_results(state: ScamState):

    print("\n====================================")
    print("LANGGRAPH RESULT AGGREGATOR")
    print("====================================")

    results = state.get(
        "results",
        []
    )

    print(
        "Number of agent results:",
        len(results)
    )

    otp_result = None
    url_result = None
    contact_result = None

    # --------------------------------------------------------
    # COLLECT RESULTS
    # --------------------------------------------------------

    for item in results:

        agent = item.get(
            "agent"
        )

        result = item.get(
            "result"
        )

        if not isinstance(result, dict):
            continue

        if agent == "OTP":

            otp_result = result

        elif agent == "URL":

            url_result = result

        elif agent == CONTACT_AGENT:

            contact_result = result

    # --------------------------------------------------------
    # PRINT WHICH AGENTS RAN
    # --------------------------------------------------------

    print(
        "OTP result:",
        "Available"
        if otp_result is not None
        else "Not used"
    )

    print(
        "URL result:",
        "Available"
        if url_result is not None
        else "Not used"
    )

    print(
        "Contact result:",
        "Available"
        if contact_result is not None
        else "Not used"
    )

    # ========================================================
    # GET RISK SCORES
    # ========================================================

    agent_scores = []
    url_score = None

    # --------------------------------------------------------
    # OTP AGENT
    #
    # OTP Agent already returns a RISK score.
    # Therefore use its score directly.
    # --------------------------------------------------------

    if otp_result is not None:

        otp_risk = _bounded_score(
            otp_result.get("score")
        )

        if otp_risk is not None:

            agent_scores.append(
                otp_risk
            )

            print(
                "OTP Risk Score:",
                otp_risk
            )

    # --------------------------------------------------------
    # URL AGENT
    #
    # URL Agent already returns a RISK score.
    # Therefore use its score directly.
    # --------------------------------------------------------

    if url_result is not None:

        url_score = _bounded_score(
            url_result.get("score")
        )

        if url_score is None:
            url_score = _bounded_score(
                url_result.get("risk_score")
            )

        if url_score is not None:

            agent_scores.append(
                url_score
            )

            print(
                "URL Risk Score:",
                url_score
            )

    # --------------------------------------------------------
    # CONTACT AGENT
    #
    # Contact Agent returns a TRUST score.
    #
    # Example:
    #
    # Contact Trust = 59
    #
    # Therefore:
    #
    # Contact Risk = 100 - 59 = 41
    #
    # --------------------------------------------------------

    if contact_result is not None:

        contact_trust = None

        # ----------------------------------------------------
        # First priority:
        # Current nested trust structure
        #
        # "trust": {
        #     "score": 59
        # }
        # ----------------------------------------------------

        trust_data = contact_result.get(
            "trust"
        )

        if isinstance(
            trust_data,
            dict
        ):

            contact_trust = _bounded_score(
                trust_data.get(
                    "score"
                )
            )

        # ----------------------------------------------------
        # Second priority:
        # trust_score
        # ----------------------------------------------------

        if contact_trust is None:

            contact_trust = _bounded_score(
                contact_result.get(
                    "trust_score"
                )
            )

        # ----------------------------------------------------
        # Third priority:
        # top-level score
        #
        # In your current runtime output, Contact Agent
        # can return:
        #
        # "score": 59
        #
        # This is still a TRUST score.
        # ----------------------------------------------------

        if contact_trust is None:

            contact_trust = _bounded_score(
                contact_result.get(
                    "score"
                )
            )

        # ----------------------------------------------------
        # Convert Contact TRUST → RISK
        # ----------------------------------------------------

        if contact_trust is not None:

            contact_risk = (
                100 - contact_trust
            )

            agent_scores.append(
                contact_risk
            )

            print(
                "Contact Trust Score:",
                contact_trust
            )

            print(
                "Contact Risk Score:",
                contact_risk
            )

    # ========================================================
    # FINAL RISK / SAFE SCORES
    # ========================================================

    if agent_scores:

        # Add the risk scores of all agents that participated.
        risk_score = sum(
            agent_scores
        )

    else:

        risk_score = 0

    # Risk must stay between 0 and 100.
    risk_score = max(
        0,
        min(
            100,
            risk_score
        )
    )

    # Safe is always the complement of risk.
    safe_score = (
        100 - risk_score
    )

    # ========================================================
    # CONFIDENCE SCORE
    # ========================================================

    confidence_scores = []

    for result in [
        otp_result,
        url_result,
        contact_result
    ]:

        if not result:
            continue

        confidence = _confidence_score(
            result.get(
                "confidence"
            )
        )

        if confidence is not None:

            confidence_scores.append(
                confidence
            )

    if confidence_scores:

        confidence_score = round(
            sum(
                confidence_scores
            )
            /
            len(
                confidence_scores
            )
        )

    else:

        confidence_score = 0

    # ========================================================
    # FINAL RISK LEVEL
    # ========================================================

    if risk_score >= 85:

        final_status = "CRITICAL"

    elif risk_score >= 65:

        final_status = "HIGH"

    elif risk_score >= 35:

        final_status = "MEDIUM"

    elif risk_score >= 15:

        final_status = "LOW"

    else:

        final_status = "SAFE"

    # ========================================================
    # COLLECT REASONS
    # ========================================================

    reasons = []

    for result in [
        otp_result,
        url_result,
        contact_result
    ]:

        if not result:
            continue

        result_reasons = result.get(
            "reasons",
            []
        )

        if isinstance(
            result_reasons,
            list
        ):

            reasons.extend(
                reason
                for reason in result_reasons
                if isinstance(
                    reason,
                    str
                )
                and reason.strip()
            )

    # Remove duplicate reasons.
    reasons = list(
        dict.fromkeys(
            reasons
        )
    )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    final_result = {

        "status": final_status,

        # Existing UI compatibility.
        # This is the FINAL RISK SCORE.
        "score": risk_score,

        # Explicit risk score.
        "risk_score": risk_score,

        # Explicit safe score.
        "safe_score": safe_score,

        # Explicit URL risk score for API and mobile consumers.
        "url_score": url_score,
        "url_risk": url_score,

        # Confidence of the participating agents.
        "confidence_score": confidence_score,

        # Combined reasons.
        "reasons": reasons,

        # Individual agent results.
        "agent_results": {

            "otp": otp_result,

            "url": url_result,

            "contact": contact_result

        }

    }

    # ========================================================
    # PRINT FINAL RESULT
    # ========================================================

    print("\n====================================")
    print("FINAL LANGGRAPH RESULT")
    print("====================================")

    print(
        "Status:",
        final_status
    )

    print(
        "Risk Score:",
        risk_score
    )

    print(
        "Safe Score:",
        safe_score
    )

    print(
        "Confidence Score:",
        confidence_score
    )

    print("\nReasons:")

    if reasons:

        for reason in reasons:

            print(
                "-",
                reason
            )

    else:

        print(
            "- No risk signals detected."
        )

    return {
        "final_result": final_result
    }


# ============================================================
# STATE
# ============================================================

class ScamState(
    TypedDict,
    total=False
):

    # Original SMS
    sms: str

    # Sender / device information
    sender: str

    expected_otp: str

    foreground_app: str

    screen_unlocked: bool

    # Contact information
    is_saved_contact: bool

    contact_name: str

    # Router information
    routes: list[str]

    # Results from individual agents
    results: Annotated[
        list[dict],
        operator.add
    ]

    # Final combined result
    final_result: dict


# ============================================================
# 1. DETECT SMS COMPONENTS
# ============================================================

def detect_components(
    state: ScamState
):

    sms = state["sms"]

    routes = []

    # --------------------------------------------------------
    # OTP DETECTION
    # --------------------------------------------------------

    otp_pattern = r"\b\d{4,8}\b"

    if re.search(
        otp_pattern,
        sms
    ):

        routes.append(
            "otp"
        )

    # --------------------------------------------------------
    # URL DETECTION
    # --------------------------------------------------------

    url_pattern = (
        r"https?://[^\s]+"
        r"|www\.[^\s]+"
        r"|\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?"
    )

    if re.search(
        url_pattern,
        sms
    ):

        routes.append(
            "url"
        )

    # --------------------------------------------------------
    # CONTACT
    # --------------------------------------------------------

    # Every SMS goes through Contact Agent.
    routes.append(
        "contact"
    )

    print("\n====================================")
    print("LANGGRAPH ROUTER")
    print("====================================")

    print(
        "SMS:"
    )

    print(
        sms
    )

    print(
        "\nDetected components:"
    )

    print(
        routes
    )

    return {
        "routes": routes
    }


# ============================================================
# 2. ROUTE TO REQUIRED AGENTS
# ============================================================

def route_agents(
    state: ScamState
):

    routes = state.get(
        "routes",
        []
    )

    destinations = []

    # --------------------------------------------------------
    # OTP AGENT
    # --------------------------------------------------------

    if "otp" in routes:

        destinations.append(
            Send(
                "otp_agent",
                dict(state)
            )
        )

    # --------------------------------------------------------
    # URL AGENT
    # --------------------------------------------------------

    if "url" in routes:

        destinations.append(
            Send(
                "url_agent",
                dict(state)
            )
        )

    # --------------------------------------------------------
    # CONTACT AGENT
    # --------------------------------------------------------

    if "contact" in routes:

        destinations.append(
            Send(
                "contact_agent",
                dict(state)
            )
        )

    return destinations


# ============================================================
# 3. OTP AGENT NODE
# ============================================================

def otp_node(
    state: ScamState
):

    print(
        "\n→ Sending SMS to OTP Agent"
    )

    result = analyze_otp(

        sender=state.get(
            "sender",
            ""
        ),

        message=state["sms"],

        expected_otp=state.get(
            "expected_otp"
        ),

        foreground_app=state.get(
            "foreground_app"
        ),

        screen_unlocked=state.get(
            "screen_unlocked",
            False
        )
    )

    return {

        "results": [

            {
                "agent": "OTP",
                "result": result
            }

        ]

    }


# ============================================================
# 4. URL AGENT NODE
# ============================================================

def url_node(
    state: ScamState
):

    print(
        "\n→ Sending SMS to URL Agent"
    )

    result = analyze_url(
        state["sms"]
    )

    return {

        "results": [

            {
                "agent": "URL",
                "result": result
            }

        ]

    }


# ============================================================
# 5. CONTACT AGENT NODE
# ============================================================

def contact_agent_node(
    state: ScamState
):

    print(
        "\n→ Sending SMS to Contact Agent"
    )

    result = analyze_contact(

        sender=state.get(
            "sender",
            ""
        ),

        message=state["sms"],

        is_saved_contact=state.get(
            "is_saved_contact",
            False
        ),

        contact_name=state.get(
            "contact_name",
            ""
        )

    )

    return {

        "results": [

            {
                "agent": CONTACT_AGENT,
                "result": result
            }

        ]

    }


# ============================================================
# 6. BUILD LANGGRAPH
# ============================================================

builder = StateGraph(
    ScamState
)


# ------------------------------------------------------------
# ADD NODES
# ------------------------------------------------------------

builder.add_node(
    "detect_components",
    detect_components
)

builder.add_node(
    "otp_agent",
    otp_node
)

builder.add_node(
    "url_agent",
    url_node
)

builder.add_node(
    "contact_agent",
    contact_agent_node
)

builder.add_node(
    "aggregate_results",
    aggregate_results
)


# ============================================================
# 7. GRAPH FLOW
# ============================================================

# ------------------------------------------------------------
# START → ROUTER
# ------------------------------------------------------------

builder.add_edge(
    START,
    "detect_components"
)


# ------------------------------------------------------------
# ROUTER → REQUIRED AGENTS
# ------------------------------------------------------------

builder.add_conditional_edges(
    "detect_components",
    route_agents
)


# ------------------------------------------------------------
# AGENTS → AGGREGATOR
# ------------------------------------------------------------

builder.add_edge(
    "otp_agent",
    "aggregate_results"
)

builder.add_edge(
    "url_agent",
    "aggregate_results"
)

builder.add_edge(
    "contact_agent",
    "aggregate_results"
)


# ------------------------------------------------------------
# AGGREGATOR → END
# ------------------------------------------------------------

builder.add_edge(
    "aggregate_results",
    END
)


# ============================================================
# 8. COMPILE LANGGRAPH
# ============================================================

scam_graph = builder.compile()