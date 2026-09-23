import sys
import os
from dotenv import load_dotenv

# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
AI_ENGINE_DIR = os.path.join(PROJECT_ROOT, "ai-engine")

# ============================================================
# LOAD BACKEND .ENV
# ============================================================

ENV_FILE = os.path.join(
    BACKEND_DIR,
    "app",
    ".env"
)

load_dotenv(ENV_FILE)

# ============================================================
# PYTHON PATH
# ============================================================

sys.path.insert(0, BACKEND_DIR)
sys.path.insert(0, AI_ENGINE_DIR)

print("GROQ KEY LOADED:", bool(os.getenv("GROQ_API_KEY")))

# ============================================================
# IMPORT LANGGRAPH
# ============================================================

from agents.langgraph_coordinator import scam_graph

# ============================================================
# TEST SMS
# ============================================================

sms = """
Your OTP is 482913. Verify your account at https://example.com
"""

result = scam_graph.invoke({
    "sms": sms,
    "sender": "+919999999999",
    "expected_otp": None,
    "foreground_app": "Messages",
    "screen_unlocked": True,
    "is_saved_contact": False,
    "contact_name": ""
})

# ============================================================
# OUTPUT
# ============================================================

print("\n\n==============================")
print("FINAL RESULT")
print("==============================")
print(result)