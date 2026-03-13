# backend/security/stepup_engine.py

class StepUpEngine:

    def evaluate(self, risk_score: float, resource_sensitivity: float):

        """
        Final enforcement decision based on:
            effective_score = risk_score × resource_sensitivity

        Range model:
            0   ≤ score ≤ 30  → allow
            31  ≤ score ≤ 55  → monitor
            56  ≤ score ≤ 70  → mfa
            71  ≤ score ≤ 85  → strong_mfa (or manager approval)
            score > 85        → block
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

        # 🟢 0 ≤ score ≤ 30 → Allow
        if 0 <= effective_score <= 30:
            return "allow"

        # 🟡 31 ≤ score ≤ 55 → Monitor
        if 31 <= effective_score <= 55:
            return "monitor"

        # 🟠 56 ≤ score ≤ 70 → Soft MFA
        if 56 <= effective_score <= 70:
            return "mfa"

        # 🔵 71 ≤ score ≤ 85 → Strong MFA or Approval
        if 71 <= effective_score <= 85:

            # High sensitivity resource escalation
            if resource_sensitivity >= 0.8:
                return "manager_approval"

            return "strong_mfa"

        # 🔴 score > 85 → Block
        return "block"