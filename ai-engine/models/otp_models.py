from dataclasses import dataclass, field
from typing import Any


@dataclass
class OTPResult:
    is_otp: bool
    score: int
    level: str
    confidence: int
    reasons: list[str] = field(default_factory=list)
    signals: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": "OTP Agent",
            "is_otp": self.is_otp,
            "score": self.score,
            "level": self.level,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "signals": self.signals,
        }