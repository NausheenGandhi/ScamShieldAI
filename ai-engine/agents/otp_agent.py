import re
from typing import Any, Dict, List, Optional


class OTPAgent:
    """
    OTP Fraud Detection Agent.

    This agent uses NLP-style text/keyword analysis and
    contextual Android signals.

    It does NOT require a training dataset.

    Inputs:
        sender
        message
        expected_otp
        foreground_app
        screen_unlocked

    Output:
        SAFE / CAUTION / DANGER / NOT_OTP
    """

    OTP_KEYWORDS = [
        "otp",
        "one time password",
        "one-time password",
        "verification code",
        "verification otp",
        "security code",
        "authentication code",
        "auth code",
        "login code",
        "login otp",
        "passcode",
        "verification passcode",
        "security otp",
        "transaction otp",
        "transaction code",
    ]

    SHARING_KEYWORDS = [
        "share the otp",
        "share otp",
        "send the otp",
        "send otp",
        "tell me the otp",
        "tell us the otp",
        "provide the otp",
        "provide otp",
        "give me the otp",
        "give us the otp",
        "read the otp",
        "read out the otp",
        "read otp",
        "forward the otp",
        "forward otp",
        "reply with the otp",
        "reply with otp",
        "send this otp",
        "send this code",
        "tell me this code",
        "tell us this code",
        "confirm the otp",
        "confirm otp",
        "confirm the code",
        "verify the otp with us",
    ]

    THIRD_PARTY_KEYWORDS = [
        "customer care",
        "customer-care",
        "customer support",
        "support agent",
        "support executive",
        "customer executive",
        "bank representative",
        "bank agent",
        "representative",
        "agent",
        "executive",
        "officer",
        "delivery agent",
        "delivery executive",
        "kyc agent",
        "verification agent",
        "technical support",
        "technical team",
        "helpdesk",
        "help desk",
    ]

    URGENCY_KEYWORDS = [
        "urgent",
        "urgently",
        "immediately",
        "immediate",
        "right now",
        "act now",
        "do it now",
        "hurry",
        "quickly",
        "as soon as possible",
        "within 2 minutes",
        "within 5 minutes",
        "within 10 minutes",
        "within minutes",
        "limited time",
        "last warning",
        "final warning",
        "important",
        "attention required",
        "immediate action",
        "action required",
        "respond immediately",
        "verify immediately",
    ]

    THREAT_KEYWORDS = [
        "account will be blocked",
        "account will be suspended",
        "account suspended",
        "account blocked",
        "account will close",
        "account closure",
        "will be blocked",
        "will be suspended",
        "will be closed",
        "account locked",
        "account will be locked",
        "card blocked",
        "card will be blocked",
        "bank account blocked",
        "bank account suspended",
        "transactions blocked",
        "transactions will be blocked",
        "transaction blocked",
        "payment blocked",
        "service terminated",
        "service will be terminated",
        "legal action",
        "penalty",
        "fine",
        "lose your money",
        "lose ur money",
        "lose money",
        "money will be lost",
        "funds will be lost",
    ]

    UNREQUESTED_KEYWORDS = [
        "didn't request",
        "did not request",
        "not requested",
        "you did not request",
        "you didn't request",
        "if you did not request",
        "if you didn't request",
        "if you have not requested",
        "if you haven't requested",
        "wasn't you",
        "was not you",
        "not you",
        "someone else",
        "unauthorized login",
        "unauthorised login",
        "unauthorized transaction",
        "unauthorised transaction",
        "unknown login",
        "unknown transaction",
        "suspicious login",
        "suspicious transaction",
    ]

    REPEATED_KEYWORDS = [
        "multiple otp",
        "multiple otps",
        "otp again",
        "otp again and again",
        "another otp",
        "another verification code",
        "new otp",
        "new verification code",
        "repeated otp",
        "repeated verification",
        "otp requests",
        "multiple requests",
        "several otp",
        "several otps",
    ]

    URL_PATTERN = re.compile(
        r"(https?://\S+|"
        r"www\.\S+|"
        r"\b[a-zA-Z0-9-]+\."
        r"(?:com|in|net|org|co|info|biz|xyz|top|site|online)"
        r"(?:/\S*)?)",
        re.IGNORECASE,
    )

    OTP_CODE_PATTERN = re.compile(
        r"\b\d{4,10}\b"
    )

    INDIAN_MOBILE_PATTERN = re.compile(
        r"^(?:\+91|91)?[6-9]\d{9}$"
    )

    # Packages where receiving an OTP is reasonably plausible.
    # Add your own banking/payment apps here.
    RELEVANT_APP_KEYWORDS = [
        "bank",
        "hdfc",
        "icici",
        "sbi",
        "axis",
        "kotak",
        "paytm",
        "phonepe",
        "googlepay",
        "gpay",
        "amazon",
        "flipkart",
        "cred",
        "paypal",
        "microsoft",
        "google",
        "instagram",
        "facebook",
        "whatsapp",
        "linkedin",
        "swiggy",
        "zomato",
        "uber",
        "ola",
    ]

    def analyze(
        self,
        sender: str,
        message: str,
        expected_otp: bool = False,
        foreground_app: str = "",
        screen_unlocked: bool = True,
    ) -> Dict[str, Any]:

        sender = str(sender or "").strip()
        message = str(message or "")
        text = message.lower().strip()

        otp_keyword_detected = self._contains_any(
            text,
            self.OTP_KEYWORDS
        )

        otp_code = self._extract_otp_code(message)

        otp_code_detected = otp_code is not None

        otp_detected = (
            otp_keyword_detected
            or otp_code_detected
        )

        if not otp_detected:
            return self._not_otp_result()

        possible_unrequested = self._contains_any(
            text,
            self.UNREQUESTED_KEYWORDS
        )

        sharing_request = self._contains_any(
            text,
            self.SHARING_KEYWORDS
        )

        third_party_request = self._contains_any(
            text,
            self.THIRD_PARTY_KEYWORDS
        )

        plain_mobile_sender = self._is_plain_mobile_number(
            sender
        )

        has_url = bool(
            self.URL_PATTERN.search(message)
        )

        urgency = self._contains_any(
            text,
            self.URGENCY_KEYWORDS
        )

        threat = self._contains_any(
            text,
            self.THREAT_KEYWORDS
        )

        repeated_otp = self._contains_any(
            text,
            self.REPEATED_KEYWORDS
        )

        relevant_foreground_app = self._is_relevant_app(
            foreground_app
        )

        # ----------------------------------------------------
        # Risk score
        # ----------------------------------------------------

        score = 0
        reasons: List[str] = []

        # User/context signal
        if expected_otp:
            reasons.append(
                "OTP appears associated with a recent user-initiated action"
            )

        elif not foreground_app:
            score += 5

            reasons.append(
                "No recent foreground app activity was detected"
            )

        elif not relevant_foreground_app:
            score += 3

            reasons.append(
                "Recent foreground app does not appear to be an OTP-related app"
            )

        # Explicit unrequested wording
        if possible_unrequested:
            score += 5

            reasons.append(
                "OTP may not have been requested by you"
            )

        # Sharing
        if sharing_request:
            score += 7

            reasons.append(
                "Message asks you to share the OTP"
            )

        # Third party
        if third_party_request:
            score += 4

            reasons.append(
                "Message refers to a customer-care representative or agent"
            )

        # Sender
        if plain_mobile_sender:
            score += 3

            reasons.append(
                "OTP came from a plain mobile number"
            )

        # URL
        if has_url:
            score += 4

            reasons.append(
                "OTP message contains a link"
            )

        # Urgency
        if urgency:
            score += 3

            reasons.append(
                "Message uses urgency or pressure"
            )

        # Threat
        if threat:
            score += 3

            reasons.append(
                "Message threatens account suspension or blocking"
            )

        # Repeated OTP
        if repeated_otp:
            score += 3

            reasons.append(
                "Message indicates repeated or multiple OTP activity"
            )

        # Locked screen
        if not screen_unlocked:
            score += 1

            reasons.append(
                "OTP arrived while the screen was locked"
            )

        # ----------------------------------------------------
        # Level
        # ----------------------------------------------------

        level = self._calculate_level(score)

        confidence = self._calculate_confidence(
            score,
            level
        )

        signals = {
            "otp_detected": True,
            "otp_code_detected": otp_code_detected,

            "expected_otp": expected_otp,
            "foreground_app": foreground_app,
            "relevant_foreground_app": relevant_foreground_app,
            "screen_unlocked": screen_unlocked,

            "possible_unrequested": possible_unrequested,
            "sharing_request": sharing_request,
            "third_party_request": third_party_request,
            "plain_mobile_sender": plain_mobile_sender,
            "has_url": has_url,
            "urgency": urgency,
            "threat": threat,
            "repeated_otp": repeated_otp,
        }

        return {
            "level": level,
            "score": score,
            "confidence": confidence,
            "otp_code": otp_code,
            "reasons": reasons,
            "signals": signals,
            "agent": "OTP Agent",
        }

    def _calculate_level(self, score: int) -> str:

        if score >= 10:
            return "DANGER"

        if score >= 4:
            return "CAUTION"

        return "SAFE"

    def _calculate_confidence(
        self,
        score: int,
        level: str
    ) -> int:

        if level == "SAFE":
            return 0

        if score >= 20:
            return 95

        if score >= 15:
            return 90

        if score >= 10:
            return 87

        if score >= 7:
            return 75

        return 60

    def _extract_otp_code(
        self,
        message: str
    ) -> Optional[str]:

        context_pattern = re.compile(
            r"(?:otp|code|passcode|verification)"
            r"(?:\s+is|\s*[:\-])?"
            r"\s*(\d{4,10})",
            re.IGNORECASE,
        )

        match = context_pattern.search(message)

        if match:
            return match.group(1)

        matches = self.OTP_CODE_PATTERN.findall(message)

        if not matches:
            return None

        return matches[0]

    @staticmethod
    def _contains_any(
        text: str,
        keywords: List[str]
    ) -> bool:

        return any(
            keyword.lower() in text
            for keyword in keywords
        )

    @classmethod
    def _is_plain_mobile_number(
        cls,
        sender: str
    ) -> bool:

        normalized = re.sub(
            r"[\s\-()]",
            "",
            sender
        )

        return bool(
            cls.INDIAN_MOBILE_PATTERN.match(
                normalized
            )
        )

    @classmethod
    def _is_relevant_app(
        cls,
        package_name: str
    ) -> bool:

        if not package_name:
            return False

        package = package_name.lower()

        return any(
            keyword in package
            for keyword in cls.RELEVANT_APP_KEYWORDS
        )

    @staticmethod
    def _not_otp_result():

        return {
            "level": "NOT_OTP",
            "score": 0,
            "confidence": 0,
            "otp_code": None,
            "reasons": [],
            "signals": {
                "otp_detected": False,
                "otp_code_detected": False,
                "expected_otp": False,
                "foreground_app": "",
                "relevant_foreground_app": False,
                "screen_unlocked": True,
                "possible_unrequested": False,
                "sharing_request": False,
                "third_party_request": False,
                "plain_mobile_sender": False,
                "has_url": False,
                "urgency": False,
                "threat": False,
                "repeated_otp": False,
            },
            "agent": "OTP Agent",
        }


# ============================================================
# GLOBAL INSTANCE
# ============================================================

otp_agent = OTPAgent()


# ============================================================
# FUNCTION USED BY FASTAPI
# ============================================================

def analyze_otp(
    sender: str = "",
    message: Optional[str] = None,
    body: Optional[str] = None,
    expected_otp: bool = False,
    foreground_app: str = "",
    screen_unlocked: bool = True,
) -> Dict[str, Any]:

    try:
        # Input validation and type checking
        sms_text = message if message is not None else body

        if sms_text is None:
            sms_text = ""

        # Ensure all inputs are proper types
        sender = str(sender or "").strip()
        sms_text = str(sms_text or "").strip()
        foreground_app = str(foreground_app or "").strip()
        expected_otp = bool(expected_otp)
        screen_unlocked = bool(screen_unlocked)

        # At least one of message or body should be present
        if not sms_text:
            return otp_agent._not_otp_result()

        return otp_agent.analyze(
            sender=sender,
            message=sms_text,
            expected_otp=expected_otp,
            foreground_app=foreground_app,
            screen_unlocked=screen_unlocked,
        )

    except Exception as e:
        print(f"OTP Agent error: {str(e)}")
        return {
            "level": "NOT_OTP",
            "score": 0,
            "confidence": 0,
            "otp_code": None,
            "reasons": [f"Analysis error: {str(e)}"],
            "signals": {
                "otp_detected": False,
                "otp_code_detected": False,
                "expected_otp": False,
                "foreground_app": "",
                "relevant_foreground_app": False,
                "screen_unlocked": True,
                "possible_unrequested": False,
                "sharing_request": False,
                "third_party_request": False,
                "plain_mobile_sender": False,
                "has_url": False,
                "urgency": False,
                "threat": False,
                "repeated_otp": False,
            },
            "agent": "OTP Agent",
        }


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    tests = [
        {
            "name": "Legitimate OTP",
            "sender": "VK-HDFCBK",
            "message":
                "Your OTP is 4821. "
                "Valid for 10 minutes. "
                "Do not share this OTP with anyone.",
            "expected_otp": True,
            "foreground_app": "com.hdfc.bank",
            "screen_unlocked": True,
        },
        {
            "name": "OTP Sharing Scam",
            "sender": "+919892126809",
            "message":
                "Your OTP is 638492749. "
                "Send this urgently or lose ur money. "
                "Customer care needs the OTP.",
            "expected_otp": False,
            "foreground_app": "",
            "screen_unlocked": True,
        },
        {
            "name": "Phishing OTP",
            "sender": "+919876543210",
            "message":
                "Your OTP is 4821. "
                "Verify your account immediately at "
                "http://fake-bank.xyz/verify "
                "or your account will be suspended.",
            "expected_otp": False,
            "foreground_app": "",
            "screen_unlocked": True,
        },
        {
            "name": "Normal SMS",
            "sender": "+919876543210",
            "message":
                "Hey, are you coming to college tomorrow?",
            "expected_otp": False,
            "foreground_app": "",
            "screen_unlocked": True,
        },
    ]

    for test in tests:

        result = analyze_otp(
            sender=test["sender"],
            message=test["message"],
            expected_otp=test["expected_otp"],
            foreground_app=test["foreground_app"],
            screen_unlocked=test["screen_unlocked"],
        )

        print("\n" + "=" * 60)
        print("TEST:", test["name"])
        print("=" * 60)

        print("OTP:", result["signals"]["otp_detected"])
        print("LEVEL:", result["level"])
        print("SCORE:", result["score"])
        print("CONFIDENCE:", f'{result["confidence"]}%')
        print("OTP CODE:", result["otp_code"])

        print("\nREASONS:")

        for reason in result["reasons"]:
            print(" •", reason)

        print("\nSIGNALS:")

        for key, value in result["signals"].items():
            print(f"  {key}: {value}")