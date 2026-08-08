import os
import sys
from typing import Optional, Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


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
# FASTAPI
# ============================================================

app = FastAPI(
    title="Scam Detection Backend",
    version="1.0.0"
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
        "otp_agent": OTP_AGENT_AVAILABLE
    }


# ============================================================
# SMS ANALYSIS
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