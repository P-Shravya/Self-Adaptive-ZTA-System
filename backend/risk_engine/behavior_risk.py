# backend/risk_engine/behavior_risk.py

def calculate_behavior_risk(meta, baseline):

    score = 0

    # 🖱 Typing deviation
    deviation = meta.get("typing_deviation", 0)
    score += deviation * 20

    # ⏳ Long Session
    avg = baseline.get("avg_session_duration", 1)
    duration = meta.get("session_duration", 0)

    if avg > 0 and duration > 4 * avg:
        score += 20

    return min(score, 20)