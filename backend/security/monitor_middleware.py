# backend/security/monitor_middleware.py

from fastapi.responses import JSONResponse
from fastapi import Request, HTTPException

from backend.auth.jwt_utils import verify_token, create_token
from backend.risk_engine.risk_engine import RiskEngine

from backend.behavior.baseline_loader import load_user_baseline
from backend.behavior.metadata_collector import collect_login_metadata  # now async
from backend.behavior.behaviorhistory_logger import log_behavior_event   # FIX: renamed

from backend.security.resource_policy import has_access
from backend.approval.approval_utils import create_approval_request
from backend.database import get_db

risk_engine = RiskEngine()


def build_pending_mfa_token(user_id, username, role, risk_score: float) -> str:
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


async def monitor_middleware(request: Request, call_next):
    """
    Adaptive Zero Trust Monitoring Middleware

    Performs:
    1. Session behavioral logging
    2. Continuous risk re-evaluation
    3. Adaptive escalation (MFA / Strong MFA / Approval)
    4. RBAC enforcement even in monitor mode
    """

    auth_header = request.headers.get("Authorization")
    path = request.url.path

    if auth_header:
        hs = auth_header.strip()
        token = None
        if hs.lower().startswith("bearer "):
            token = hs[7:].strip() or None
        if token:
            payload = verify_token(token)
        else:
            payload = None

    if auth_header and token:

        # Poll endpoint must bypass RBAC (non-manager roles cannot access /api/approvals/*).
        if payload and path.startswith("/api/approvals/status"):
            return await call_next(request)

        # Pre-approval JWT: only status polling is allowed — not dashboard, MFA, or data APIs.
        if payload and payload.get("approval_pending"):
            return JSONResponse(
                status_code=403,
                content={
                    "detail": {
                        "status": "manager_approval_required",
                        "message": "Awaiting manager approval. You cannot use the app until approved.",
                    }
                },
            )

        # MFA routes are not listed in ROLE_ACCESS. Any valid JWT (pending MFA
        # step-up or normal session) may call /mfa/*; binding is enforced in
        # mfa_router (sub must match user_id).
        if payload and path.startswith("/mfa/"):
            return await call_next(request)

        if payload:
            user_id = payload.get("sub")
            username = payload.get("username")
            role = payload.get("role")

            # =========================================
            # 1️⃣ RBAC ENFORCEMENT (Always apply)
            # =========================================

            if not has_access(role, path):
                raise HTTPException(
                    status_code=403,
                    detail="Access denied for your role."
                )

            # =========================================
            # 2️⃣ MONITOR MODE CHECK
            # =========================================

            if payload.get("monitor"):

                # =====================================
                # 3️⃣ COLLECT RUNTIME METADATA
                # FIX: collect_login_metadata is now async (uses httpx + cache).
                # Must be awaited. The geo result is cached per IP so the
                # external HTTP call only fires once per IP per 5 minutes,
                # eliminating the per-request blocking latency that was the
                # most severe performance issue in monitored sessions.
                # =====================================

                metadata = await collect_login_metadata(
                    request=request,
                    user_id=user_id,
                    username=username
                )

                metadata["action"] = "monitor_api_activity"

                # =====================================
                # 4️⃣ LOG SESSION ACTIVITY
                # FIX: use renamed log_behavior_event
                # =====================================

                log_behavior_event(metadata)

                # =====================================
                # 5️⃣ LOAD USER BASELINE
                # =====================================

                baseline_raw = load_user_baseline(user_id)

                if baseline_raw:

                    baseline = {
                        "avg_login_hour": baseline_raw["temporal"]["login_hours"]["mean"],
                        "login_hour_std": baseline_raw["temporal"]["login_hours"]["std"],
                        "known_devices": baseline_raw["device"]["known_devices"],
                        "avg_session_duration": baseline_raw["session"]["avg_duration"],
                        "avg_data_transfer": baseline_raw["data"]["avg_data_transfer"],
                        "avg_download_volume": baseline_raw["data"]["avg_download_volume"]
                    }

                    # =====================================
                    # 6️⃣ CONTINUOUS RISK RE-EVALUATION
                    # =====================================

                    risk_result = risk_engine.evaluate(metadata, baseline)
                    risk_score = risk_result["score"]

                    # =====================================
                    # 7️⃣ ADAPTIVE ESCALATION LOGIC
                    # =====================================

                    # Level 1 escalation: MFA
                    if 56 <= risk_score <= 70:
                        # If user hasn't enrolled MFA yet, return
                        # mfa_setup_required so frontend shows OTP page with a
                        # "Setup MFA" CTA.
                        enrolled_mfa = False
                        try:
                            conn = get_db()
                            cursor = conn.cursor()
                            cursor.execute(
                                "SELECT mfa_secret, mfa_enabled FROM users WHERE id=?",
                                (user_id,)
                            )
                            row = cursor.fetchone()
                            conn.close()
                            enrolled_mfa = bool(row["mfa_secret"]) and int(row["mfa_enabled"] or 0) == 1
                        except Exception:
                            enrolled_mfa = False

                        status = "mfa_required" if enrolled_mfa else "mfa_setup_required"
                        return JSONResponse(
                            status_code=401,
                            content={"detail": {
                                "status": status,
                                "methods": ["totp"],
                                "user_id": user_id,
                                "risk_score": risk_score,
                                "pending_mfa_token": build_pending_mfa_token(
                                    user_id=user_id,
                                    username=username,
                                    role=role,
                                    risk_score=risk_score
                                )
                            }}
                        )

                    # Level 2 escalation: Strong MFA (aligned with StepUpEngine: < 86)
                    if 71 <= risk_score < 86:
                        return JSONResponse(
                            status_code=401,
                            content={"detail": {
                                "status": "strong_mfa_required",
                                "methods": ["biometric", "email_otp"],
                                "message": "Strong MFA required. Risk score is high.",
                                "user_id": user_id,
                                "risk_score": risk_score,
                                "pending_mfa_token": build_pending_mfa_token(
                                    user_id=user_id,
                                    username=username,
                                    role=role,
                                    risk_score=risk_score
                                )
                            }}
                        )

                    # Level 3 escalation: Manager Approval
                    if 86 <= risk_score <= 95:
                        create_approval_request(
                            user_id=user_id,
                            resource=request.url.path,
                            risk_score=risk_score
                        )

                        return JSONResponse(
                            status_code=403,
                            content={"detail": {
                                "status": "manager_approval_required",
                                "user_id": user_id,
                                "risk_score": risk_score
                            }}
                        )

                    if risk_score > 95:
                        return JSONResponse(
                            status_code=403,
                            content={"detail": {
                                "status": "blocked",
                                "user_id": user_id,
                                "risk_score": risk_score,
                                "message": "Risk score too high; request blocked."
                            }}
                        )

    response = await call_next(request)

    return response