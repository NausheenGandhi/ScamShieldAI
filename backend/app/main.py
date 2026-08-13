import os
import sys
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

# use importlib to attempt importing from the ai-engine/agents package
import importlib

try:
    module = importlib.import_module("agents.otp_agent")
    analyze_otp = getattr(module, "analyze_otp")
    OTP_AGENT_AVAILABLE = True
except Exception as e:
    OTP_AGENT_AVAILABLE = False
    analyze_otp = None
    print("OTP Agent import failed:", str(e))


# ============================================================
# URL AGENT
# ============================================================
#
# IMPORTANT:
# DO NOT CHANGE YOUR EXISTING URL AGENT.
#
# It continues using your existing Groq implementation.
# ============================================================

try:
    module = importlib.import_module("agents.url_agent")
    analyze_url = getattr(module, "analyze_url")
    URL_AGENT_AVAILABLE = True
except Exception as e:
    URL_AGENT_AVAILABLE = False
    analyze_url = None
    print("URL Agent import failed:", str(e))


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


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "status": "running",
        "service": "Scam Detection Backend",

        "agents": {
            "otp": OTP_AGENT_AVAILABLE,
            "url": URL_AGENT_AVAILABLE,
        }
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {

        "status": "healthy",

        "otp_agent":
            OTP_AGENT_AVAILABLE,

        "url_agent":
            URL_AGENT_AVAILABLE,
    }


# ============================================================
# SMS ANALYSIS
# OTP AGENT
# ============================================================

@app.post("/analyze-sms")
def analyze_sms(
    request: SMSRequest
):

    print("\n")

    print("=" * 70)

    print("NEW SMS - OTP ANALYSIS")

    print("=" * 70)


    print(
        "Sender:",
        request.sender
    )


    # ========================================================
    # IMPORTANT PRIVACY NOTE
    # ========================================================
    #
    # SmsReceiver.kt should already sanitize the OTP.
    #
    # Example received by backend:
    #
    # "Your OTP is [OTP]. Give me the OTP."
    #
    # NOT:
    #
    # "Your OTP is 482193. Give me the OTP."
    #
    # Therefore the actual OTP should NEVER appear here.
    # ========================================================

    print(
        "Sanitized Message:",
        request.body
    )


    print(
        "Expected OTP:",
        request.expected_otp
    )


    print(
        "Foreground App:",
        request.foreground_app
    )


    print(
        "Screen Unlocked:",
        request.screen_unlocked
    )


    # ========================================================
    # CHECK OTP AGENT
    # ========================================================

    if not OTP_AGENT_AVAILABLE:

        raise HTTPException(

            status_code=500,

            detail="OTP Agent is unavailable"
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
    # OTP AGENT
    # ========================================================

    try:

        result = analyze_otp(

            sender=
                request.sender,

            message=
                request.body,

            expected_otp=
                request.expected_otp,

            foreground_app=
                request.foreground_app,

            screen_unlocked=
                request.screen_unlocked,
        )


    except Exception as e:

        print(
            "OTP Agent error:",
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
        "OTP RESULT"
    )

    print(
        "-" * 70
    )

    print(
        result
    )


    return result


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


    # IMPORTANT:
    # URL Agent receives the ORIGINAL SMS.
    #
    # SmsReceiver.kt calls this endpoint with
    # originalBody, not sanitizedBody.

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

