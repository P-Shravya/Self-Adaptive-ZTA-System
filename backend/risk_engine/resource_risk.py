# backend/risk_engine/resource_risk.py

RESOURCE_SENSITIVITY = {
    "dashboard": 0.2,
    "patient_records": 0.6,
    "payroll": 0.9,
    "admin": 1.0
}

def calculate_resource_risk(meta):

    flags = []

    # 🔴 Privilege Escalation
    if meta.get("privilege_escalation"):
        flags.append("privilege_escalation")
        return 100, flags

    resource = meta.get("resource", "dashboard")
    sensitivity = RESOURCE_SENSITIVITY.get(resource, 0.2)

    score = sensitivity * 40

    return min(score, 40), flags