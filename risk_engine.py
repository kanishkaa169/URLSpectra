class RiskEngine:
    def __init__(self):
        self.score = 0
        self.reasons = []

    def add(self, message, points):
        self.score += points
        self.reasons.append(message)

    def get_level(self):
        if self.score <= 1:
            return "LOW"
        elif self.score <= 3:
            return "MEDIUM"
        else:
            return "HIGH"


def get_risk_level(score):
    if score <= 1:
        return "LOW"
    elif score <= 3:
        return "MEDIUM"
    else:
        return "HIGH"

def add_warning(message, points):
    print("⚠️ Warning:", message)
    return points