import os
import json
import logging
from typing import Dict, Any

from openai import OpenAI
from dotenv import load_dotenv


# ----------------------------------------------------
# Logging Setup
# ----------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("ai_policy_engine")


# ----------------------------------------------------
# Load Environment Variables
# ----------------------------------------------------
BASE_DIR = os.path.dirname(__file__)
ENV_PATH = os.path.join(BASE_DIR, "..", ".env")

load_dotenv(dotenv_path=ENV_PATH)

API_KEY = os.getenv("OPENAI_API_KEY")

if not API_KEY:
    raise RuntimeError(
        "OPENAI_API_KEY not found. Please add it to backend/.env"
    )


# ----------------------------------------------------
# OpenAI Client
# ----------------------------------------------------
client = OpenAI(
    api_key=API_KEY,
    timeout=10
)


# ----------------------------------------------------
# Allowed Actions
# ----------------------------------------------------
VALID_ACTIONS = {
    "allow",
    "monitor",
    "mfa",
    "strong_mfa",
    "manager_approval",
    "block"
}


# ----------------------------------------------------
# AI Policy Engine
# ----------------------------------------------------
class AIPolicyEngine:

    def generate_policy(
        self,
        meta: Dict[str, Any],
        baseline: Dict[str, Any],
        risk_score: float,
        flags: Dict[str, Any]
    ) -> Dict[str, Any]:

        try:

            prompt = self.build_prompt(meta, baseline, risk_score, flags)

            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an Adaptive Zero Trust AI Policy Engine."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.2,
                max_tokens=200,
                response_format={"type": "json_object"}
            )

            content = response.choices[0].message.content

            if not content:
                raise ValueError("Empty AI response")

            decision = json.loads(content)

            decision = self.validate_decision(decision)

            logger.info("AI Decision Generated: %s", decision)

            return decision

        except Exception as e:

            logger.error("AI POLICY ERROR: %s", str(e))

            return self.fallback_policy()

    # ----------------------------------------------------
    # Prompt Builder
    # ----------------------------------------------------
    def build_prompt(self, meta, baseline, risk_score, flags):

        login_type = meta.get("action", "login_success")

        safe_meta = json.dumps(meta, indent=2)
        safe_baseline = json.dumps(baseline, indent=2)
        safe_flags = json.dumps(flags, indent=2)

        return f"""
Analyze the following login attempt and generate an adaptive Zero Trust decision.

LOGIN TYPE: {login_type}

Risk Score: {risk_score}

Flags:
{safe_flags}

Login Metadata:
{safe_meta}

User Baseline:
{safe_baseline}

Decision Guidelines:

If LOGIN TYPE is "login_failed":
- Consider failed_attempts carefully.
- 1–2 attempts: likely mistype → allow retry or monitor.
- 3–5 attempts: suspicious → monitor or require MFA.
- 6+ attempts: high risk → block or strong_mfa.
- If combined with VPN or abnormal IP → escalate faster.
- If rapid repeated attempts → possible brute force.

If LOGIN TYPE is "login_success":
- Compare login time with baseline average.
- Check for new device.
- Check geographic deviation.
- If minor anomaly → monitor.
- If major anomaly → mfa or strong_mfa.
- If extreme anomaly → block.

Respond ONLY with valid JSON in this format:

{{
  "action": "allow | monitor | mfa | strong_mfa | manager_approval | block",
  "additional_controls": [],
  "reasoning": "Short explanation",
  "confidence": 0.0
}}
"""

    # ----------------------------------------------------
    # Validate AI Output
    # ----------------------------------------------------
    def validate_decision(self, decision):

        if not isinstance(decision, dict):
            return self.fallback_policy()

        action = decision.get("action", "mfa")

        if action not in VALID_ACTIONS:
            action = "mfa"

        reasoning = decision.get(
            "reasoning",
            "AI decision applied"
        )

        confidence = decision.get("confidence", 0.5)

        try:
            confidence = float(confidence)
        except Exception:
            confidence = 0.5

        additional_controls = decision.get(
            "additional_controls",
            []
        )

        return {
            "action": action,
            "additional_controls": additional_controls,
            "reasoning": reasoning,
            "confidence": confidence
        }

    # ----------------------------------------------------
    # Safe Fallback Policy
    # ----------------------------------------------------
    def fallback_policy(self):

        return {
            "action": "mfa",
            "additional_controls": [],
            "reasoning": "Fallback policy due to AI failure",
            "confidence": 0.0
        }