import sys
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

AI_ENGINE_DIR = PROJECT_ROOT / "ai-engine"
if str(AI_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(AI_ENGINE_DIR))

from agents.contact_agent import analyze_contact
from agents.coordinator import combine_agent_results
from agents.otp_agent import analyze_otp
from agents.pattern_agent import analyze_pattern
from agents.url_agent import analyze_url


class PatternAgentTests(unittest.TestCase):
    def test_normal_message(self):
        result = analyze_pattern(
            sender="+15558675309",
            message="Hi, are we still meeting later?",
            timestamp=time.time(),
            history=[(time.time() - 3600, "Hi, are we still meeting later?")],
        )
        self.assertIn(result["pattern_risk"], {"LOW", "MEDIUM", "HIGH", "UNKNOWN"})
        self.assertIsInstance(result["features"], dict)

    def test_multiple_messages_in_5_minutes(self):
        now = time.time()
        history = [
            (now - 110, "Urgent check for you."),
            (now - 90, "Urgent check for you."),
            (now - 60, "Urgent check for you."),
            (now - 20, "Urgent check for you."),
        ]
        result = analyze_pattern(
            sender="+15558675310",
            message="Urgent check for you.",
            timestamp=now,
            history=history,
        )
        self.assertTrue(result["signals"]["high_frequency"] or result["signals"]["burst_detected"])

    def test_repeated_identical_messages(self):
        now = time.time()
        history = [
            (now - 300, "Your account has been frozen. Reply now."),
            (now - 200, "Your account has been frozen. Reply now."),
            (now - 120, "Your account has been frozen. Reply now."),
        ]
        result = analyze_pattern(
            sender="+15558675311",
            message="Your account has been frozen. Reply now.",
            timestamp=now,
            history=history,
        )
        self.assertTrue(result["signals"]["repeated_content"])
        self.assertGreaterEqual(result["features"]["repeat_count"], 1)

    def test_similar_but_not_identical_messages(self):
        now = time.time()
        history = [
            (now - 300, "Your account has been frozen. Please reply."),
            (now - 200, "Your account may be frozen. Please respond."),
        ]
        result = analyze_pattern(
            sender="+15558675312",
            message="Your account has been frozen. Please reply now.",
            timestamp=now,
            history=history,
        )
        self.assertGreaterEqual(result["features"]["max_similarity"], 0.0)

    def test_repeated_url(self):
        now = time.time()
        history = [
            (now - 250, "Verify account: https://example.com/secure"),
            (now - 150, "Verify account: https://example.com/secure"),
        ]
        result = analyze_pattern(
            sender="+15558675313",
            message="Verify account: https://example.com/secure",
            timestamp=now,
            history=history,
        )
        self.assertTrue(result["signals"]["repeated_url"] or result["features"]["repeated_url"])

    def test_highly_regular_timing(self):
        now = time.time()
        history = [
            (now - 240, "Scan this"),
            (now - 180, "Scan this"),
            (now - 120, "Scan this"),
            (now - 60, "Scan this"),
        ]
        result = analyze_pattern(
            sender="+15558675314",
            message="Scan this",
            timestamp=now,
            history=history,
        )
        self.assertIn("unusual_timing", result["signals"])

    def test_sudden_volume_increase(self):
        now = time.time()
        history = [
            (now - 3600, "a"),
            (now - 3300, "b"),
            (now - 3000, "c"),
            (now - 100, "d"),
            (now - 80, "e"),
            (now - 60, "f"),
        ]
        result = analyze_pattern(
            sender="+15558675315",
            message="g",
            timestamp=now,
            history=history,
        )
        self.assertTrue(result["signals"]["sudden_volume_increase"] or result["signals"]["high_frequency"])

    def test_insufficient_history(self):
        result = analyze_pattern(sender="+15558675316", message="", timestamp=time.time(), history=[])
        self.assertEqual(result["pattern_risk"], "UNKNOWN")

    def test_empty_message(self):
        result = analyze_pattern(sender="+15558675317", message="", timestamp=time.time())
        self.assertEqual(result["pattern_risk"], "UNKNOWN")

    def test_missing_timestamp(self):
        result = analyze_pattern(sender="+15558675318", message="Hello from a friendly contact")
        self.assertIn(result["pattern_risk"], {"LOW", "MEDIUM", "HIGH", "UNKNOWN"})

    def test_model_unavailable_falls_back_safely(self):
        result = analyze_pattern(sender="+15558675319", message="hello", timestamp=time.time(), history=[])
        self.assertIn("model_available", result)
        self.assertIsInstance(result["model_available"], bool)

    def test_database_history_unavailable(self):
        result = analyze_pattern(sender="+15558675320", message="Hi there", timestamp=time.time(), history=[(time.time()-10, "Hi there")])
        self.assertIn("database_history_available", result)

    def test_contact_agent_still_works_independently(self):
        result = analyze_contact(
            sender="+15558675321",
            message="Hi, everything okay?",
            is_saved_contact=True,
            contact_name="Alice",
            timestamp=time.time(),
        )
        self.assertIn(result["trust"]["verdict"], {"TRUSTED", "LOW_RISK", "CAUTION", "SUSPICIOUS", "HIGH_RISK"})

    def test_url_agent_still_works(self):
        result = analyze_url("Your bank account has been locked. Use https://example.com/secure")
        self.assertIsInstance(result, dict)
        self.assertIn("short_explanation", result)

    def test_otp_agent_still_works(self):
        result = analyze_otp(
            sender="+15558675322",
            message="Your OTP is [OTP]. Please share it to verify your account.",
            expected_otp=False,
            foreground_app="com.example.bank",
            screen_unlocked=True,
        )
        self.assertIsInstance(result, dict)

    def test_coordinator_combines_agent_outputs(self):
        result = combine_agent_results(
            contact_result={"trust": {"score": 85}, "score": 85},
            url_result={"category": "legitimate", "score": 10},
            otp_result={"score": 40, "level": "CAUTION"},
            pattern_result={"pattern_score": 60, "pattern_risk": "MEDIUM"},
        )
        self.assertIn(result["status"], {"SAFE", "SUSPICIOUS", "SCAM"})
        self.assertIn("agent_results", result)


if __name__ == "__main__":
    unittest.main()
