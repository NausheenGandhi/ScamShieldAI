from agents.otp_agent import OTPAgent


agent = OTPAgent()


messages = [

    {
        "name": "Legitimate OTP",
        "sender": "VM-HDFCBK",
        "body": (
            "Your OTP is 4821. "
            "Valid for 10 minutes. "
            "Do not share this OTP with anyone."
        ),
        "context": {
            "possible_unrequested": False,
            "recent_otp_count": 1,
        },
    },

    {
        "name": "OTP sharing scam",
        "sender": "9876543210",
        "body": (
            "URGENT! Your HDFC account will be "
            "SUSPENDED. Contact customer care "
            "and share the OTP immediately."
        ),
        "context": {
            "possible_unrequested": True,
            "recent_otp_count": 1,
        },
    },

    {
        "name": "Phishing OTP",
        "sender": "9876543210",
        "body": (
            "Your account will be SUSPENDED "
            "within 24 hours. Verify now at "
            "http://hdfc-secure-login.example "
            "and share the OTP."
        ),
        "context": {
            "possible_unrequested": True,
            "recent_otp_count": 1,
        },
    },

    {
        "name": "Normal SMS",
        "sender": "VM-HDFCBK",
        "body": (
            "Your monthly account statement "
            "is ready."
        ),
        "context": {
            "possible_unrequested": False,
            "recent_otp_count": 1,
        },
    },
]


for test in messages:

    result = agent.analyze(
        sender=test["sender"],
        body=test["body"],
        context=test["context"],
    )

    print("\n" + "=" * 60)

    print(
        f"TEST: {test['name']}"
    )

    print(
        f"OTP: {result.is_otp}"
    )

    print(
        f"LEVEL: {result.level}"
    )

    print(
        f"SCORE: {result.score}"
    )

    print(
        f"CONFIDENCE: {result.confidence}%"
    )

    print("REASONS:")

    for reason in result.reasons:
        print(
            f"  • {reason}"
        )

    print("SIGNALS:")

    for name, value in result.signals.items():
        print(
            f"  {name}: {value}"
        )