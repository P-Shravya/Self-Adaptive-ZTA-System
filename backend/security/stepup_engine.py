# backend/security/stepup_engine.py

class StepUpEngine:

    def evaluate(self, risk_score: float, resource_sensitivity: float):

        """
        Final enforcement decision based on:
            effective_score = risk_score × resource_sensitivity

        Range model (continuous; avoids gaps like 85.1 falling through):
            score ≤ 30        → allow
            31–55             → monitor
            56–70             → mfa
            71–85.x           → strong_mfa (everything below 86)
            86–95             → manager_approval
            score > 95        → block
        """

        # ------------------------------------------
        # 1️⃣ Calculate Effective Risk
        # ------------------------------------------
        effective_score = risk_score * resource_sensitivity

        # Safety clamp (optional but good practice)
        effective_score = max(0, min(effective_score, 100))

        # ------------------------------------------
        # 2️⃣ Decision Based on Effective Score
        # ------------------------------------------

        if effective_score <= 30:
            return "allow"

        if effective_score <= 55:
            return "monitor"

        if effective_score <= 70:
            return "mfa"

        # Strong MFA for high-but-not-critical scores (includes e.g. 85.12)
        if effective_score < 86:
            return "strong_mfa"

        if effective_score <= 95:
            return "manager_approval"

        return "block"