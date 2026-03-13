# backend/risk_engine/risk_config.py

CATEGORY_CAPS = {
    "identity": 40,
    "device": 30,
    "network": 30,
    "resource": 40,
    "behavior": 20,
    "data": 50,
}

CRITICAL_OVERRIDES = [
    "privilege_escalation",
    "token_replay",
    "rooted_device",
    "credential_stuffing",
    "impossible_travel",
    "sanctioned_country"
]

DECISION_THRESHOLDS = {
    "allow": 30,
    "monitor": 55,
    "mfa": 70,
    "restricted": 85,
    "block": 100
}