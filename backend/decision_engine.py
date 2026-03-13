from backend.ai.ai_policy_engine import AIPolicyEngine
from backend.risk_engine.risk_config import CRITICAL_OVERRIDES


class DecisionEngine:

    def __init__(self, stepup_engine):
        self.ai_engine = AIPolicyEngine()
        self.stepup_engine = stepup_engine

    def decide(self, meta, baseline, risk_score, flags):

        # Critical override
        for flag in flags:
            if flag in CRITICAL_OVERRIDES:
                return {
                    "action": "block",
                    "risk_score": 100
                }

        resource_sensitivity = meta.get("resource_sensitivity", 1)

        action = self.stepup_engine.evaluate(
            risk_score,
            resource_sensitivity
        )

        return {
            "action": action,
            "risk_score": risk_score
        }
from backend.ai.ai_policy_engine import AIPolicyEngine
from backend.risk_engine.risk_config import CRITICAL_OVERRIDES


class DecisionEngine:

    def __init__(self, stepup_engine):
        self.ai_engine = AIPolicyEngine()
        self.stepup_engine = stepup_engine

    def decide(self, meta, baseline, risk_score, flags):

        login_type = meta.get("action", "login_success")

        # ==========================================
        # 🔴 1️⃣ HARD CRITICAL OVERRIDE
        # ==========================================
        for flag in flags:
            if flag in CRITICAL_OVERRIDES:
                return {
                    "action": "block",
                    "risk_score": 100,
                    "reasoning": "Critical override triggered",
                    "confidence": 1.0
                }

        # ==========================================
        # 🔹 2️⃣ FAILED LOGIN LOGIC (Hybrid AI)
        # ==========================================
        if login_type == "login_failed":

            # Hard safety guardrail
            if meta.get("failed_attempts", 0) >= 10:
                return {
                    "action": "block",
                    "risk_score": risk_score,
                    "reasoning": "Exceeded maximum failed attempts",
                    "confidence": 1.0
                }

            # Always invoke AI for failed login
            try:
                ai_decision = self.ai_engine.generate_policy(
                    meta, baseline, risk_score, flags
                )
                ai_decision["risk_score"] = risk_score
                ai_decision["ai_generated"] = True
                return ai_decision

            except Exception as e:
                print("AI FAILED (login_failed):", e)
                return {
                    "action": "block",
                    "risk_score": risk_score,
                    "reasoning": "AI failure fallback (failed login)",
                    "confidence": 0.0
                }

        # ==========================================
        # 🔹 3️⃣ SUCCESSFUL LOGIN LOGIC
        # ==========================================

        # Risk tiers for successful login
        if risk_score < 40:
            static_action = "allow"

        elif 40 <= risk_score < 70:
            static_action = "monitor"

        elif 70 <= risk_score < 85:
            static_action = "mfa"

        elif 85 <= risk_score < 95:
            static_action = "strong_mfa"

        else:
            static_action = "block"

        # ==========================================
        # 🔹 4️⃣ Decide Whether To Invoke AI
        # ==========================================

        if self.should_invoke_ai(risk_score, flags, meta):

            try:
                ai_decision = self.ai_engine.generate_policy(
                    meta, baseline, risk_score, flags
                )

                ai_decision["risk_score"] = risk_score
                ai_decision["ai_generated"] = True

                return ai_decision

            except Exception as e:
                print("AI FAILED (login_success):", e)

                return {
                    "action": static_action,
                    "risk_score": risk_score,
                    "reasoning": "AI failure fallback (static decision used)",
                    "confidence": 0.5,
                    "ai_generated": False
                }

        # ==========================================
        # 🔹 5️⃣ Static Decision (No AI Needed)
        # ==========================================

        return {
            "action": static_action,
            "risk_score": risk_score,
            "reasoning": "Static risk-based decision",
            "confidence": 0.7,
            "ai_generated": False
        }

    # ==========================================
    # 🔹 AI INVOCATION RULES
    # ==========================================
    def should_invoke_ai(self, risk_score, flags, meta):

        # Always invoke AI for login_failed
        if meta.get("action") == "login_failed":
            return True

        # Invoke AI for medium-high risk
        if 60 <= risk_score <= 95:
            return True

        # Invoke AI if multiple risk signals
        if len(flags) >= 3:
            return True

        # Invoke AI if behavioral anomaly
        if "behavioral_drift" in flags:
            return True

        return False