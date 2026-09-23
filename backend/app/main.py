import os
import sys
import importlib
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from dotenv import load_dotenv

load_dotenv()


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

AI_ENGINE_DIR = os.path.join(
    PROJECT_ROOT,
    "ai-engine"
)

if AI_ENGINE_DIR not in sys.path:
    sys.path.insert(0, AI_ENGINE_DIR)


# ============================================================
# OTP AGENT
# ============================================================

try:
    module = importlib.import_module("agents.otp_agent")
    analyze_otp = getattr(module, "analyze_otp")
    OTP_AGENT_AVAILABLE = True

except Exception as e:
    OTP_AGENT_AVAILABLE = False
    analyze_otp = None

    print(
        "OTP Agent import failed:",
        str(e)
    )


# ============================================================
# URL AGENT
# ============================================================

#
# IMPORTANT:
# DO NOT CHANGE YOUR EXISTING URL AGENT.
#
# It continues using your existing implementation.
#

try:
    module = importlib.import_module("agents.url_agent")
    analyze_url = getattr(module, "analyze_url")
    URL_AGENT_AVAILABLE = True

except Exception as e:
    URL_AGENT_AVAILABLE = False
    analyze_url = None

    print(
        "URL Agent import failed:",
        str(e)
    )


# ============================================================
# CONTACT AGENT
# ============================================================

try:
    module = importlib.import_module("agents.contact_agent")
    analyze_contact = getattr(
        module,
        "analyze_contact"
    )

    CONTACT_AGENT_AVAILABLE = True

except Exception as e:
    CONTACT_AGENT_AVAILABLE = False
    analyze_contact = None

    print(
        "Contact Agent import failed:",
        str(e)
    )


# ============================================================
# PATTERN AGENT
# ============================================================

try:
    module = importlib.import_module("agents.pattern_agent")
    analyze_pattern = getattr(module, "analyze_pattern")
    PATTERN_AGENT_AVAILABLE = True

except Exception as e:
    PATTERN_AGENT_AVAILABLE = False
    analyze_pattern = None

    print(
        "Pattern Agent import failed:",
        str(e)
    )

# ============================================================
# LANGGRAPH COORDINATOR
# ============================================================

try:
    module = importlib.import_module(
        "agents.langgraph_coordinator"
    )

    scam_graph = getattr(
        module,
        "scam_graph"
    )

    LANGGRAPH_AVAILABLE = True

except Exception as e:
    LANGGRAPH_AVAILABLE = False
    scam_graph = None

    print(
        "LangGraph Coordinator import failed:",
        str(e)
    )



# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="Scam Detection Backend",
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)


# ============================================================
# SMS REQUEST
# ============================================================

class SMSRequest(BaseModel):

    sender: str

    body: str

    timestamp: Optional[int] = None

    source: Optional[str] = (
        "android_sms_receiver"
    )

    expected_otp: bool = False

    foreground_app: str = ""

    screen_unlocked: bool = True

    # ========================================================
    # CONTACT AGENT SIGNALS
    # ========================================================
    #
    # These values are computed on the Android device.
    #

    is_saved_contact: bool = False

    contact_name: Optional[str] = None


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {

        "status": "running",

        "service":
            "Scam Detection Backend",

        "agents": {

            "otp":
                OTP_AGENT_AVAILABLE,

            "url":
                URL_AGENT_AVAILABLE,

            "contact":
                CONTACT_AGENT_AVAILABLE,

            "pattern":
                PATTERN_AGENT_AVAILABLE,

          "langgraph":
    LANGGRAPH_AVAILABLE,
        }
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {

        "status":
            "healthy",

        "otp_agent":
            OTP_AGENT_AVAILABLE,

        "url_agent":
            URL_AGENT_AVAILABLE,

        "contact_agent":
            CONTACT_AGENT_AVAILABLE,

        "pattern_agent":
            PATTERN_AGENT_AVAILABLE,

        "langgraph":
            LANGGRAPH_AVAILABLE,
    }


# ============================================================
# SMS ANALYSIS
# OTP AGENT
# ============================================================

# ============================================================
# SMS ANALYSIS
# LANGGRAPH COORDINATOR
# ============================================================

@app.post("/analyze-sms")
def analyze_sms(
    request: SMSRequest
):

    print("\n")
    print("=" * 70)
    print("NEW SMS - LANGGRAPH ANALYSIS")
    print("=" * 70)

    print("Sender:", request.sender)
    print("Message:", request.body)
    print("Expected OTP:", request.expected_otp)
    print("Foreground App:", request.foreground_app)
    print("Screen Unlocked:", request.screen_unlocked)
    print("Saved Contact:", request.is_saved_contact)
    print("Contact Name:", request.contact_name)

    # ========================================================
    # CHECK LANGGRAPH
    # ========================================================

    if not LANGGRAPH_AVAILABLE:
        raise HTTPException(
            status_code=500,
            detail="LangGraph Coordinator is unavailable"
        )

    # ========================================================
    # BASIC VALIDATION
    # ========================================================

    if (
        not request.body
        or not request.body.strip()
    ):
        raise HTTPException(
            status_code=400,
            detail="body must not be empty"
        )

    # ========================================================
    # LANGGRAPH
    # ========================================================

    try:

        graph_result = scam_graph.invoke({

            "sms": request.body,

            "sender": request.sender,

            "expected_otp": request.expected_otp,

            "foreground_app": request.foreground_app,

            "screen_unlocked": request.screen_unlocked,

            "is_saved_contact":
                request.is_saved_contact,

            "contact_name":
                request.contact_name or "",
        })

    except Exception as e:

        print(
            "LangGraph error:",
            str(e)
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    final_result = graph_result.get(
        "final_result",
        {}
    )

    print("\n")
    print("=" * 70)
    print("LANGGRAPH FINAL RESULT")
    print("=" * 70)

    print(final_result)

    # ========================================================
    # RESPONSE TO REACT NATIVE
    # ========================================================

    return {
        "success": True,

        "sms": {
            "sender": request.sender,
            "body": request.body,
            "timestamp": request.timestamp,
        },

        "analysis": final_result,

        "routes": graph_result.get(
            "routes",
            []
        ),

        "agents": graph_result.get(
            "results",
            []
        ),
    }


# ============================================================
# URL ANALYSIS
# ============================================================
#
# IMPORTANT:
#
# THIS SECTION IS YOUR EXISTING URL AGENT.
#
# DO NOT CHANGE ITS BEHAVIOR.
# ============================================================

@app.post("/analyze-url")
def analyze_url_endpoint(
    request: SMSRequest
):

    print("\n")

    print("=" * 70)

    print(
        "NEW URL/SMS ANALYSIS REQUEST"
    )

    print("=" * 70)


    print(
        "Sender:",
        request.sender
    )


    # ========================================================
    # IMPORTANT:
    #
    # URL Agent receives the ORIGINAL SMS.
    #
    # SmsReceiver.kt calls this endpoint with
    # originalBody, not sanitizedBody.
    # ========================================================

    print(
        "Message:",
        request.body
    )


    # ========================================================
    # CHECK URL AGENT
    # ========================================================

    if not URL_AGENT_AVAILABLE:

        raise HTTPException(

            status_code=500,

            detail="URL Agent is unavailable"
        )


    # ========================================================
    # VALIDATE MESSAGE
    # ========================================================

    if (
        not request.body
        or not request.body.strip()
    ):

        raise HTTPException(

            status_code=400,

            detail="body must not be empty"
        )


    # ========================================================
    # EXISTING URL AGENT
    # ========================================================

    try:

        result = analyze_url(
            request.body
        )


    except Exception as e:

        print(
            "URL Agent error:",
            str(e)
        )

        raise HTTPException(

            status_code=500,

            detail=str(e)
        )


    # ========================================================
    # PRINT RESULT
    # ========================================================

    print("\n")

    print(
        "URL RESULT"
    )

    print(
        "-" * 70
    )

    print(
        result
    )


    return result


# ============================================================
# PATTERN ANALYSIS
# ============================================================

@app.post("/analyze-pattern")
def analyze_pattern_endpoint(
    request: SMSRequest
):
    print("\n")
    print("=" * 70)
    print("NEW PATTERN ANALYSIS REQUEST")
    print("=" * 70)

    if not PATTERN_AGENT_AVAILABLE:
        raise HTTPException(status_code=500, detail="Pattern Agent is unavailable")

    if not request.body or not request.body.strip():
        raise HTTPException(status_code=400, detail="body must not be empty")

    ts_seconds = request.timestamp / 1000 if request.timestamp else None

    try:
        result = analyze_pattern(
            sender=request.sender,
            message=request.body,
            timestamp=ts_seconds,
        )
    except Exception as e:
        print("Pattern Agent error:", str(e))
        raise HTTPException(status_code=500, detail=str(e))

    print("\n")
    print("PATTERN RESULT")
    print("-" * 70)
    print(result)

    return result


# ============================================================
# CONTACT ANALYSIS
# ============================================================

@app.post("/analyze-contact")
def analyze_contact_endpoint(
    request: SMSRequest
):

    print("\n")

    print("=" * 70)

    print(
        "NEW CONTACT ANALYSIS REQUEST"
    )

    print("=" * 70)


    print(
        "Sender:",
        request.sender
    )


    print(
        "Saved contact:",
        request.is_saved_contact
    )


    print(
        "Contact name:",
        request.contact_name
    )


    # ========================================================
    # CHECK CONTACT AGENT
    # ========================================================

    if not CONTACT_AGENT_AVAILABLE:

        raise HTTPException(

            status_code=500,

            detail="Contact Agent is unavailable"
        )


    # ========================================================
    # BASIC VALIDATION
    # ========================================================

    if (
        not request.body
        or not request.body.strip()
    ):

        raise HTTPException(

            status_code=400,

            detail="body must not be empty"
        )


    # ========================================================
    # CONVERT TIMESTAMP
    # ========================================================
    #
    # Kotlin sends epoch milliseconds.
    #
    # Contact Agent expects seconds.
    #

    ts_seconds = (
        request.timestamp / 1000
        if request.timestamp
        else None
    )


    # ========================================================
    # CONTACT AGENT
    # ========================================================

    try:

        result = analyze_contact(

            sender=
                request.sender,

            message=
                request.body,

            is_saved_contact=
                request.is_saved_contact,

            contact_name=
                request.contact_name,

            timestamp=
                ts_seconds,
        )


    except Exception as e:

        print(
            "Contact Agent error:",
            str(e)
        )

        raise HTTPException(

            status_code=500,

            detail=str(e)
        )


    # ========================================================
    # PRINT RESULT
    # ========================================================

    print("\n")

    print(
        "CONTACT RESULT"
    )

    print(
        "-" * 70
    )

    print(
        result
    )


    return result