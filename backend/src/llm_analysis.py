import re


INDICATOR_RULES = [
    (
        "Urgency / pressure language",
        ["urgent", "immediately", "asap", "within 24 hours", "within 12 hours", "expires", "suspended", "final notice"],
        "high",
        "Uses pressure to make the reader act before verifying the request.",
    ),
    (
        "Credential request",
        ["password", "verify your account", "confirm your credentials", "login", "re-validate", "ssn", "seed phrase", "private key"],
        "high",
        "Requests credentials or sensitive identity information.",
    ),
    (
        "Account suspension lure",
        ["account suspended", "account locked", "unusual activity", "verify identity", "security alert"],
        "high",
        "Claims account risk to force the recipient into a login or verification flow.",
    ),
    (
        "Financial lure",
        ["bank", "wire transfer", "invoice", "payment required", "customs fee", "gift card", "bitcoin", "refund"],
        "medium",
        "Introduces a money-related reason for the user to take action.",
    ),
    (
        "Generic greeting",
        ["dear user", "dear customer", "dear client", "dear sir", "dear madam"],
        "low",
        "Uses generic language instead of a personalized recipient.",
    ),
]

URL_REGEX = re.compile(r"https?://[^\s)>\"']+", re.IGNORECASE)
IP_URL_REGEX = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.IGNORECASE)
SUSPICIOUS_TLDS = (".ru", ".tk", ".xyz", ".info", ".top", ".click", ".co")
AUTHORITY_SENDER_REGEX = re.compile(r"(ceo|admin|support|security|helpdesk|microsoft|paypal|dhl|bank|chase)", re.IGNORECASE)
FREE_OR_RISKY_DOMAIN_REGEX = re.compile(r"(gmail|yahoo|outlook|hotmail|protonmail|\.tk|\.ru|\.xyz|\.info)", re.IGNORECASE)


def extract_urls(email_text: str) -> list[str]:
    return URL_REGEX.findall(email_text)


def extract_indicators(email_text: str) -> list[dict]:
    lower = email_text.lower()
    indicators: list[dict] = []

    for label, terms, severity, detail in INDICATOR_RULES:
        matches = [term for term in terms if term in lower]
        if matches:
            indicators.append(
                {
                    "label": label,
                    "detail": f"{detail} Detected terms: {', '.join(matches[:4])}.",
                    "severity": severity,
                }
            )

    urls = extract_urls(email_text)
    if urls:
        if IP_URL_REGEX.search(email_text):
            indicators.append(
                {
                    "label": "Raw IP address in link",
                    "detail": "A link points directly to an IP address, which is uncommon in legitimate email.",
                    "severity": "high",
                }
            )

        suspicious_url = next(
            (
                url
                for url in urls
                if any(url.lower().endswith(tld) or f"{tld}/" in url.lower() for tld in SUSPICIOUS_TLDS)
            ),
            None,
        )
        if suspicious_url:
            indicators.append(
                {
                    "label": "Suspicious link domain",
                    "detail": f"Unusual or high-risk link domain observed: {suspicious_url[:80]}.",
                    "severity": "high",
                }
            )

    from_match = re.search(r"from:\s*([^<\n]+)<?([^>\n]*)>?", email_text, re.IGNORECASE)
    if from_match:
        display_name = from_match.group(1)
        address = from_match.group(2)
        if AUTHORITY_SENDER_REGEX.search(display_name) and FREE_OR_RISKY_DOMAIN_REGEX.search(address):
            indicators.append(
                {
                    "label": "Spoofed or mismatched sender",
                    "detail": f"Sender display name claims authority but address appears risky: {address.strip()}.",
                    "severity": "high",
                }
            )

    if not indicators:
        indicators.append(
            {
                "label": "No strong phishing indicators",
                "detail": "The message does not match the current demo rules for common phishing language.",
                "severity": "low",
            }
        )

    return indicators


def indicator_risk_boost(indicators: list[dict]) -> int:
    boost = 0
    for indicator in indicators:
        if indicator["label"] == "No strong phishing indicators":
            continue
        if indicator["severity"] == "high":
            boost += 12
        elif indicator["severity"] == "medium":
            boost += 7
        else:
            boost += 3
    return min(boost, 35)


def analyze_email(email_text: str, classification: str, indicators: list[dict] | None = None) -> str:
    indicators = indicators or extract_indicators(email_text)
    suspicious = [item for item in indicators if item["label"] != "No strong phishing indicators"]

    if classification == "Phishing":
        if suspicious:
            explanation = (
                "The email contains social engineering patterns commonly found in phishing. "
                f"Key indicators include: {', '.join(item['label'] for item in suspicious[:4])}."
            )
        else:
            explanation = (
                "The ML model classified the message as phishing based on learned text patterns, "
                "although the rule-based indicator layer found only weak explicit signals."
            )
        mitre = "Initial Access (TA0001)"
    else:
        explanation = (
            "The email is classified as safe because the phishing probability is low and no strong "
            "credential, urgency, spoofing, or suspicious link pattern dominates the message."
        )
        mitre = "No clear MITRE ATT&CK tactic detected"

    return (
        f"Classification: {classification}\n"
        f"Explanation: {explanation}\n"
        f"MITRE ATT&CK: {mitre}"
    )
