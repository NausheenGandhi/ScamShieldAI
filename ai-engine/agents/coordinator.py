from typing import Any, Dict, List, Optional


def _coerce_numeric(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalize_contact_trust(contact_result: Optional[Dict[str, Any]]) -> float:
    if not contact_result:
        return 0.0

    trust = contact_result.get("trust") or {}
    score = _coerce_numeric(trust.get("score"), contact_result.get("score", 0))
    return max(0.0, min(100.0, 100.0 - score))


def _normalize_url_risk(url_result: Optional[Dict[str, Any]]) -> float:
    if not url_result:
        return 0.0

    category = str(url_result.get("category", "unknown")).lower()
    if category in {"phishing", "scam"}:
        return 95.0
    if category == "spam":
        return 70.0
    if category == "legitimate":
        return 10.0

    risk_score = _coerce_numeric(url_result.get("risk_score"), url_result.get("score", 0))
    return max(0.0, min(100.0, risk_score))


def _normalize_otp_risk(otp_result: Optional[Dict[str, Any]]) -> float:
    if not otp_result:
        return 0.0

    score = _coerce_numeric(otp_result.get("score"), 0)
    if score:
        return max(0.0, min(100.0, score))

    level = str(otp_result.get("level", "SAFE")).upper()
    mapping = {
        "DANGER": 90.0,
        "HIGH_RISK": 90.0,
        "CAUTION": 60.0,
        "SAFE": 10.0,
        "LOW_RISK": 20.0,
        "NOT_OTP": 5.0,
        "ERROR": 50.0,
    }
    return mapping.get(level, 0.0)


def _normalize_pattern_risk(pattern_result: Optional[Dict[str, Any]]) -> float:
    if not pattern_result:
        return 0.0

    pattern_score = _coerce_numeric(pattern_result.get("pattern_score"), pattern_result.get("score", 0))
    if pattern_score:
        return max(0.0, min(100.0, pattern_score))

    risk = str(pattern_result.get("pattern_risk", "LOW")).upper()
    mapping = {"HIGH": 85.0, "MEDIUM": 55.0, "LOW": 20.0, "UNKNOWN": 15.0}
    return mapping.get(risk, 0.0)


def combine_agent_results(
    contact_result: Optional[Dict[str, Any]] = None,
    url_result: Optional[Dict[str, Any]] = None,
    otp_result: Optional[Dict[str, Any]] = None,
    pattern_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    contact_risk = _normalize_contact_trust(contact_result)
    url_risk = _normalize_url_risk(url_result)
    otp_risk = _normalize_otp_risk(otp_result)
    pattern_risk = _normalize_pattern_risk(pattern_result)

    # Weighted blend. Higher total risk means more dangerous.
    weighted = (
        contact_risk * 0.25
        + url_risk * 0.30
        + otp_risk * 0.25
        + pattern_risk * 0.20
    )

    score = int(round(max(0.0, min(100.0, weighted))))

    if score >= 75:
        final_status = "SCAM"
    elif score >= 45:
        final_status = "SUSPICIOUS"
    else:
        final_status = "SAFE"

    reasons: List[str] = []
    if contact_result:
        reasons.append("Contact trust signal evaluated.")
    if url_result:
        reasons.append("URL risk signal evaluated.")
    if otp_result:
        reasons.append("OTP intent signal evaluated.")
    if pattern_result:
        reasons.append("Pattern behavior signal evaluated.")

    return {
        "status": final_status,
        "score": score,
        "contact_risk": round(contact_risk, 1),
        "url_risk": round(url_risk, 1),
        "otp_risk": round(otp_risk, 1),
        "pattern_risk": round(pattern_risk, 1),
        "reasons": reasons,
        "agent_results": {
            "contact": contact_result,
            "url": url_result,
            "otp": otp_result,
            "pattern": pattern_result,
        },
    }


analyze_coordinator = combine_agent_results
