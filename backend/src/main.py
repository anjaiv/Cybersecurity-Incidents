from datetime import datetime

from .llm_analysis import analyze_email, extract_indicators, indicator_risk_boost
from .ml_model import PHISHING_LABEL, predict_with_confidence


def threat_from_risk(risk_score: int) -> str:
    if risk_score > 90:
        return "HIGH"
    if risk_score > 70:
        return "MEDIUM"
    return "LOW"


def analyze_full(email_text: str) -> dict:
    indicators = extract_indicators(email_text)
    prediction = predict_with_confidence(email_text)
    phishing_probability = prediction["phishing_probability"]

    # Blend ML probability with clear rule-based phishing signals. This keeps the thesis
    # demo robust on short emails while the ML model remains the primary classifier.
    base_risk = round(phishing_probability * 100)
    risk_score = min(100, base_risk + indicator_risk_boost(indicators))
    ml_result = "Phishing" if prediction["label"] == PHISHING_LABEL or risk_score >= 70 else "Safe"
    threat_level = threat_from_risk(risk_score)
    llm_result = analyze_email(email_text, ml_result, indicators)

    return {
        "input_email": email_text,
        "ml_result": ml_result,
        "confidence": prediction["confidence"],
        "risk_score": risk_score,
        "threat_level": threat_level,
        "llm_result": llm_result,
        "mitre_mapping": "Initial Access (TA0001)"
        if ml_result == "Phishing"
        else "No clear MITRE ATT&CK tactic detected",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "indicators": indicators,
        "model_details": {
            "raw_label": prediction["label"],
            "phishing_probability": prediction["phishing_probability"],
            "safe_probability": prediction["safe_probability"],
            "risk_adjustment": risk_score - base_risk,
        },
    }
