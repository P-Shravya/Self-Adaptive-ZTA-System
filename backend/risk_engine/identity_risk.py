# backend/risk_engine/identity_risk.py


def calculate_identity_risk(meta: dict, baseline: dict, db=None):
    """
    FIX: `db` is now an optional parameter.
    Callers (e.g. risk_engine.py) should pass the already-open DB connection
    so this function does not open its own. This eliminates the 3-concurrent-
    connections-per-login problem (auth_router + metadata_collector + identity_risk).
    If db is None we open one as a fallback for backward compatibility.
    """

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
        penalty = 10 * (2 ** (attempts - 1))
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
    # FIX: use the passed-in db connection when available to avoid opening
    # a new SQLite connection per risk evaluation call.
    # ==========================================
    _owns_db = False
    try:
        if db is None:
            from backend.database import get_db
            db = get_db()
            _owns_db = True

        recent_logs = db.execute("""
            SELECT action
            FROM behavior_logs
            WHERE user_id=?
            ORDER BY timestamp DESC
            LIMIT 5
        """, (meta.get("user_id"),)).fetchall()

        recent_failed = sum(
            1 for r in recent_logs if r["action"] == "login_failed"
        )

        if recent_failed >= 3:
            risk += 30
            flags.append("brute_force_pattern")

    except Exception:
        pass
    finally:
        if _owns_db and db:
            db.close()

    # ==========================================
    # 5️⃣ LOGIN TIME ANOMALY (Z-Score)
    # ==========================================
    avg_hour = baseline.get("avg_login_hour")
    std_dev = baseline.get("login_hour_std", 1)
    login_hour = meta.get("login_hour")

    if avg_hour is not None and login_hour is not None:
        # FIX: clamp std_dev to a minimum of 1.0 so the Z-score cannot
        # explode when the baseline has very little variance (e.g. a user
        # who always logs in at exactly the same hour gives std_dev ≈ 0).
        std_dev = max(float(std_dev), 1.0)

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