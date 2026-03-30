from datetime import datetime
from fastapi import APIRouter, HTTPException, Request

from backend.database import get_db
from backend.auth.password_utils import verify_password
from backend.auth.jwt_utils import create_token

# 🔹 Behavior Layer
from backend.behavior.metadata_collector import (
    collect_login_metadata,
    generate_device_id,
    extract_ip_prefix
)
from backend.behavior.behaviorhistory_logger import log_behavior_event  # FIX: renamed
from backend.behavior.baseline_loader import load_user_baseline          # FIX: load cached baseline
from backend.behavior.userbaseline_builder import build_user_baseline

# 🔹 Security Layers
from backend.risk_engine.risk_engine import RiskEngine
from backend.security.stepup_engine import StepUpEngine
from backend.approval.approval_utils import create_approval_request
from backend.security.resource_policy import get_resource_sensitivity


router = APIRouter()

risk_engine = RiskEngine()
stepup_engine = StepUpEngine()

# FIX: Fixed sensitivity used at login time so step-up can actually fire.
# /api/login sensitivity (0.2) multiplied against risk nearly never triggered
# step-up. Using 1.0 means the raw risk score drives the decision directly.
LOGIN_SENSITIVITY = 1.0

def build_pending_mfa_token(user_id: int, username: str, role: str, risk_score: float) -> str:
    return create_token(
        {
            "sub": user_id,
            "username": username,
            "role": role,
            "risk_score": float(risk_score),
            "mfa_pending": True
        },
        expiry_minutes=60
    )


# ==========================================
# 🔹 Baseline Normalization
# ==========================================
def normalize_baseline(raw_baseline):
    if not raw_baseline:
        return {}

    return {
        "avg_login_hour": raw_baseline["temporal"]["login_hours"]["mean"],
        "login_hour_std": raw_baseline["temporal"]["login_hours"]["std"],
        "known_devices": raw_baseline["device"]["known_devices"],
        "avg_session_duration": raw_baseline["session"]["avg_duration"],
        "avg_data_transfer": raw_baseline["data"]["avg_data_transfer"],
        "avg_download_volume": raw_baseline["data"]["avg_download_volume"]
    }


# ==========================================
# 🔹 LOGIN ROUTE
# ==========================================
@router.post("/api/login")
async def login(data: dict, request: Request):

    db = get_db()
    cursor = db.cursor()

    try:
        # =====================================
        # 1️⃣ VERIFY USER EXISTS
        # =====================================
        user = cursor.execute(
            """
            SELECT id, username, password_hash, role, failed_attempts,
                 mfa_secret, mfa_enabled
            FROM users
            WHERE email=?
            """,
            (data["email"],)
        ).fetchone()

        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # =====================================
        # 2️⃣ VERIFY PASSWORD
        # =====================================
        if not verify_password(data["password"], user["password_hash"]):

            # Increment failed counter
            cursor.execute(
                "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id=?",
                (user["id"],)
            )
            db.commit()

            # Get updated failed count
            updated_user = cursor.execute(
                "SELECT failed_attempts FROM users WHERE id=?",
                (user["id"],)
            ).fetchone()

            # FIX: renamed log_successful_login → log_behavior_event to avoid
            # the misleading name. Same function, now named accurately.
            failed_metadata = {
                "user_id": user["id"],
                "username": user["username"],
                "timestamp": datetime.utcnow().isoformat(),
                "hour": datetime.utcnow().hour,
                "day_of_week": datetime.utcnow().weekday(),

                "ip_address": request.client.host,
                "ip_prefix": extract_ip_prefix(request.client.host),
                "location_country": None,
                "latitude": None,
                "longitude": None,

                "geo_distance_km": 0,
                "time_diff_minutes": 0,

                "device_id": generate_device_id(
                    request.headers.get("user-agent", ""),
                    request.client.host
                ),
                "device_type": None,
                "os": None,
                "browser": None,

                "resource": request.url.path,
                "action": "login_failed",

                "session_id": None,
                "session_duration": 0,

                "vpn_detected": 0,
                "proxy_detected": 0,

                "failed_attempts": updated_user["failed_attempts"],

                "typing_avg": 0,
                "data_transfer": 0,
                "download_volume": 0
            }

            log_behavior_event(failed_metadata)

            raise HTTPException(status_code=401, detail="Invalid credentials")

        # =====================================
        # 3️⃣ SUCCESSFUL LOGIN
        # =====================================

        # Save previous failed attempts BEFORE reset
        previous_failed_attempts = user["failed_attempts"]

        # Reset failed counter
        cursor.execute(
            "UPDATE users SET failed_attempts = 0 WHERE id=?",
            (user["id"],)
        )
        db.commit()

    finally:
        # FIX: always close the DB opened at the top of the route,
        # regardless of which branch is taken (fail, success, or exception).
        db.close()

    # =====================================
    # 4️⃣ COLLECT LOGIN METADATA
    # =====================================
    metadata = await collect_login_metadata(
        request=request,
        user_id=user["id"],
        username=user["username"]
    )

    # Attach historical failed count
    metadata["failed_attempts"] = previous_failed_attempts

    # =====================================
    # 5️⃣ STORE LOGIN HISTORY
    # =====================================
    log_behavior_event(metadata)

    # =====================================
    # 6️⃣ LOAD CACHED BASELINE (rebuild only if missing)
    # FIX: previously called build_user_baseline() on every login, which
    # fetched 30 rows, computed stats, and wrote to DB each time.
    # Now we load the pre-built baseline; only rebuild when absent.
    # =====================================
    raw_baseline = load_user_baseline(user["id"])
    if not raw_baseline:
        raw_baseline = build_user_baseline(user["id"])
    baseline = normalize_baseline(raw_baseline)

    # =====================================
    # 7️⃣ EVALUATE RISK
    # =====================================
    risk_result = risk_engine.evaluate(metadata, baseline)
    risk_score = risk_result["score"]

    # FIX: use LOGIN_SENSITIVITY (1.0) instead of the resource path sensitivity
    # (which was always 0.2 for /api/login, making step-up nearly impossible).
    # Step-up at login is driven purely by the raw risk score.
    action = stepup_engine.evaluate(risk_score, LOGIN_SENSITIVITY)

    # =====================================
    # 8️⃣ HANDLE DECISIONS
    # =====================================

    if action == "block":
        raise HTTPException(status_code=403, detail="High Risk Login Blocked")

    if action == "monitor":
        token = create_token({
            "sub": user["id"],
            "username": user["username"],
            "role": user["role"],
            "monitor": True,
            "risk_score": risk_score
        }, expiry_minutes=30)      # 🔥 Short session for monitored users
        return {
            "access_token": token,
            "token_type": "bearer",
            "risk_score": risk_score,
            "mode": "monitor"
        }

    if action == "mfa":

        # If user has not configured MFA yet
        if not user["mfa_secret"] or user["mfa_enabled"] == 0:
            return {
                "status": "mfa_setup_required",
                "user_id": user["id"],
                "risk_score": risk_score,
                "pending_mfa_token": build_pending_mfa_token(
                    user_id=user["id"],
                    username=user["username"],
                    role=user["role"],
                    risk_score=risk_score
                )
            }

        # If MFA already configured
        return {
            "status": "mfa_required",
            "methods": ["totp"],
            "user_id": user["id"],
            "risk_score": risk_score,
            "pending_mfa_token": build_pending_mfa_token(
                user_id=user["id"],
                username=user["username"],
                role=user["role"],
                risk_score=risk_score
            )
        }

    if action == "strong_mfa":

        if not user["mfa_secret"] or user["mfa_enabled"] == 0:
            return {
                "status": "mfa_setup_required",
                "user_id": user["id"],
                "risk_score": risk_score,
                "pending_mfa_token": build_pending_mfa_token(
                    user_id=user["id"],
                    username=user["username"],
                    role=user["role"],
                    risk_score=risk_score
                )
            }

        return {
            "status": "strong_mfa_required",
            "methods": ["webauthn"],
            "user_id": user["id"],
            "risk_score": risk_score
        }

    if action == "manager_approval":
        resource = metadata.get("resource", "/api/login")
        create_approval_request(
            user_id=user["id"],
            resource=resource,
            risk_score=risk_score
        )
        return {
            "status": "manager_approval_required",
            "risk_score": risk_score
        }

    # Default: ALLOW
    token = create_token({
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"],
        "risk_score": risk_score
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "risk_score": risk_score,
        "message": "Login successful"
    }