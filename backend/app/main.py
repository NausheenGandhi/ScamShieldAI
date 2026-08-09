import os
import sys
from typing import Optional, Any

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

    from agents.otp_agent import analyze_otp

    OTP_AGENT_AVAILABLE = True

except Exception as e:

    OTP_AGENT_AVAILABLE = False

    print(
        "OTP Agent import failed:",
        str(e)
    )


# ============================================================
# URL AGENT
# ============================================================

try:

    from agents.url_agent import analyze_url

    URL_AGENT_AVAILABLE = True

except Exception as e:

    URL_AGENT_AVAILABLE = False

    print(
        "URL Agent import failed:",
        str(e)
    )


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="Scam Detection Backend",
    version="1.0.0"
)

# Mobile app hits this from a phone on the LAN / a dev tunnel, so it's
# a different origin than the API by definition. Locked down to "*"
# for development; replace with your actual app's origin(s) before
# shipping a production build.
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
        "service": "Scam Detection Backend"
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "otp_agent": OTP_AGENT_AVAILABLE,
        "url_agent": URL_AGENT_AVAILABLE,
    }


# ============================================================
# SMS ANALYSIS (OTP-focused)
# ============================================================

@app.post("/analyze-sms")
def analyze_sms(
    request: SMSRequest
):

    print("\n")
    print("=" * 70)
    print("NEW SMS")
    print("=" * 70)

    print("Sender:", request.sender)
    print("Message:", request.body)
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

    if not OTP_AGENT_AVAILABLE:

        raise HTTPException(
            status_code=500,
            detail="OTP Agent is unavailable"
        )

    try:

        result = analyze_otp(
            sender=request.sender,
            message=request.body,
            expected_otp=request.expected_otp,
            foreground_app=request.foreground_app,
            screen_unlocked=request.screen_unlocked,
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

    print("\nOTP RESULT")
    print("-" * 70)
    print(result)

    return result


# ============================================================
# URL ANALYSIS (phishing / spam / legitimate + AI explanation)
# ============================================================
# Handles the general "explain this SMS to me" case: works whether or
# not the message actually contains a link (url_agent.analyze_url()
# still runs brand-impersonation / urgency detection when there's no
# URL). This is what ScanScreen.js and the SMS-history / real-time
# screens call to get a short_explanation for a message.

@app.post("/analyze-url")
def analyze_url_endpoint(
    request: SMSRequest
):

    print("\n")
    print("=" * 70)
    print("NEW URL/SMS ANALYSIS REQUEST")
    print("=" * 70)

    print("Sender:", request.sender)
    print("Message:", request.body)

    if not URL_AGENT_AVAILABLE:

        raise HTTPException(
            status_code=500,
            detail="URL Agent is unavailable"
        )

    if not request.body or not request.body.strip():

        raise HTTPException(
            status_code=400,
            detail="body must not be empty"
        )

    try:

        result = analyze_url(request.body)

    except Exception as e:

        print(
            "URL Agent error:",
            str(e)
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

    print("\nURL RESULT")
    print("-" * 70)
    print(result)

    return result