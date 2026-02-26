# backend/risk_engine/identity_risk.py

from backend.database import get_db


def calculate_identity_risk(meta: dict, baseline: dict):

    risk = 0
    flags = []

    # ==========================================
    # 1️⃣ IMPOSSIBLE TRAVEL (Hard Override)
    # ==========================================
    geo_distance = meta.get("geo_distance_km", 0)
    time_diff = meta.get("time_diff_minutes", 999)

    if time_diff < 30 and geo_distance > 1500:
        flags.append("impossible_travel")
        return {
            "risk": 100,
            "flags": flags
        }

    # ==========================================
    # 2️⃣ COUNTRY RISK (If Implemented)
    # ==========================================
    geo_risk = meta.get("country_risk", 0)  # 0–1
    risk += 40 * geo_risk

    # ==========================================
    # 3️⃣ FAILED ATTEMPTS (Controlled Exponential)
    # ==========================================
    attempts = meta.get("failed_attempts", 0)

    if attempts > 0:
        # Controlled exponential growth
        penalty = 10 * (2 ** (attempts - 1))

        # Cap exponential part
        penalty = min(penalty, 60)

        risk += penalty

        if attempts > 5:
            flags.append("excessive_failed_attempts")
        elif attempts > 2:
            flags.append("moderate_failed_attempts")
        else:
            flags.append("minor_failed_attempts")

    # ==========================================
    # 4️⃣ CONTINUOUS FAILURE PATTERN
    # ==========================================
    try:
        db = get_db()
        recent_logs = db.execute("""
            SELECT action
            FROM behavior_logs
            WHERE user_id=?
            ORDER BY timestamp DESC
            LIMIT 5
        """, (meta.get("user_id"),)).fetchall()
        db.close()

        recent_failed = sum(
            1 for r in recent_logs if r["action"] == "login_failed"
        )

        if recent_failed >= 3:
            risk += 30
            flags.append("brute_force_pattern")

    except Exception:
        pass

    # ==========================================
    # 5️⃣ LOGIN TIME ANOMALY (Z-Score)
    # ==========================================
    avg_hour = baseline.get("avg_login_hour")
    std_dev = baseline.get("login_hour_std", 1)
    login_hour = meta.get("login_hour")

    if avg_hour is not None and login_hour is not None:

        if std_dev == 0:
            std_dev = 1

        z = abs(login_hour - avg_hour) / std_dev

        if z > 2:
            risk += min(z * 10, 25)
            flags.append("login_time_anomaly")

    # ==========================================
    # 6️⃣ FINAL CAP
    # ==========================================
    risk = min(risk, 100)

    return {
        "risk": risk,
        "flags": flags
    }