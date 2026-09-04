def detect_attack_intent(url):
    url_lower = url.lower()

    intents = []

    if any(word in url_lower for word in ["login", "signin", "password"]):
        intents.append("Credential Theft")

    if any(word in url_lower for word in ["bank", "payment", "card", "upi"]):
        intents.append("Financial Fraud")

    if any(word in url_lower for word in ["download", ".exe", ".zip"]):
        intents.append("Malware Delivery")

    if any(word in url_lower for word in ["verify-account", "reset-password"]):
        intents.append("Account Takeover")

    if any(word in url_lower for word in ["prize", "winner", "reward"]):
        intents.append("Scam / Fake Reward")

    if not intents:
        return ["No specific attack intent detected"]

    return intents