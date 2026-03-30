import logging
from backend.ai.ai_policy_engine import AIPolicyEngine
from backend.risk_engine.risk_config import CRITICAL_OVERRIDES

# ----------------------------------------------------
# Logging
# ----------------------------------------------------
logger = logging.getLogger("decision_engine")

# ----------------------------------------------------
# Allowed actions
# ----------------------------------------------------
VALID_ACTIONS = {
    "allow",
    "monitor",
    "mfa",
    "strong_mfa",
    "manager_approval",
    "block"
}
class DecisionEngine:
    def __init__(self, stepup_engine=None):
        self.ai_engine = AIPolicyEngine()
        self.stepup_engine = stepup_engine
    # ----------------------------------------------------
    # Main Decision Logic
    # ----------------------------------------------------
    def decide(self, meta, baseline, risk_score, flags):
        login_type = meta.get("action", "login_success")
        # ==========================================
        # 1️⃣ Critical Override
        # ==========================================
        for flag in flags:
            if flag in CRITICAL_OVERRIDES:
                logger.warning("Critical override triggered: %s", flag)
                return {
                    "action": "block",
                    "risk_score": 100,
                    "reasoning": "Critical override triggered",
                    "confidence": 1.0,
                    "ai_generated": False
                }
        # ==========================================
        # 2️⃣ Failed Login Handling
        # ==========================================
        if login_type == "login_failed":
            failed_attempts = meta.get("failed_attempts", 0)
            # Hard guardrail
            if failed_attempts >= 10:
                return {
                    "action": "block",
                    "risk_score": risk_score,
                    "reasoning": "Exceeded maximum failed login attempts",
                    "confidence": 1.0,
                    "ai_generated": False
                }
            return self.invoke_ai(meta, baseline, risk_score, flags)
        # ==========================================
        # 3️⃣ Static Risk-Based Decision
        # ==========================================
        static_action = self.static_decision(risk_score)
        # ==========================================
        # 4️⃣ AI Invocation Decision
        # ==========================================
        if self.should_invoke_ai(risk_score, flags, meta):
            ai_result = self.invoke_ai(meta, baseline, risk_score, flags)
            if ai_result:
                return ai_result
        # ==========================================
        # 5️⃣ Static Decision Fallback
        # ==========================================
        return {
            "action": static_action,
            "risk_score": risk_score,
            "reasoning": "Static risk-based decision",
            "confidence": 0.7,
            "ai_generated": False
        }
    # ----------------------------------------------------
    # Static Decision Rules
    # ----------------------------------------------------
    def static_decision(self, risk_score):
        if risk_score < 40:
            return "allow"
        elif risk_score < 70:
            return "monitor"
        elif risk_score < 85:
            return "mfa"
        elif risk_score < 95:
            return "strong_mfa"
        else:
            return "block"
    # ----------------------------------------------------
    # AI Invocation
    # ----------------------------------------------------
    def invoke_ai(self, meta, baseline, risk_score, flags):
        try:
            ai_decision = self.ai_engine.generate_policy(
                meta,
                baseline,
                risk_score,
                flags
            )
            if not ai_decision:
                raise ValueError("Empty AI response")

            action = ai_decision.get("action", "mfa")
            if action not in VALID_ACTIONS:
                action = "mfa"
            ai_decision["action"] = action
            ai_decision["risk_score"] = risk_score
            ai_decision["ai_generated"] = True
            logger.info("AI decision applied: %s", ai_decision)
            return ai_decision
        except Exception as e:
            logger.error("AI invocation failed: %s", str(e))
            return {
                "action": "mfa",
                "risk_score": risk_score,
                "reasoning": "AI failure fallback",
                "confidence": 0.3,
                "ai_generated": False
            }
    # ----------------------------------------------------
    # AI Invocation Rules
    # ----------------------------------------------------
    def should_invoke_ai(self, risk_score, flags, meta):
        login_type = meta.get("action")
        # Always for failed logins
        if login_type == "login_failed":
            return True
        # Medium-high risk
        if 60 <= risk_score <= 95:
            return True
        # Multiple anomalies
        if len(flags) >= 3:
            return True
        # Behavioral anomaly
        if "behavioral_drift" in flags:
            return True
        return False