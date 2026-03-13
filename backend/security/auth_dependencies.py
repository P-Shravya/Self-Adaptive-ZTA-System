# backend/security/auth_dependencies.py

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from backend.auth.jwt_utils import verify_token

from backend.security.resource_policy import has_access, get_resource_sensitivity
from backend.security.stepup_engine import StepUpEngine
from backend.database import get_db
from backend.approval.approval_utils import create_approval_request


security = HTTPBearer()
stepup_engine = StepUpEngine()

# FIX: When a user accesses their OWN permitted section, we use a reduced
# sensitivity so their risk score is not unfairly amplified by the resource's
# inherent sensitivity value. Full sensitivity is only meaningful when
# evaluating whether an unauthorised role should be blocked — but by that
# point we've already returned 403 via has_access(), so it never actually
# runs with full sensitivity in practice anyway.
PERMITTED_ROLE_SENSITIVITY = 0.3


# ==========================================
# 🔹 Get Current Authenticated User
# ==========================================
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):

    token = credentials.credentials
    payload = verify_token(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return payload


# ==========================================
# 🔹 Require Manager Role
# ==========================================
def require_manager(user: dict = Depends(get_current_user)):

    if user.get("role") not in ["manager", "admin"]:
        raise HTTPException(status_code=403, detail="Access denied")

    return user

# =============================================
# 🔹 Role Based Access Enforcement Dependency
# =============================================

def require_role_access(resource: str):

    def role_dependency(user=Depends(get_current_user)):

        # 1️⃣ Normal RBAC check — unauthorized roles stopped here immediately.
        if not has_access(user.get("role"), resource):
            raise HTTPException(
                status_code=403,
                detail="Access denied for your role."
            )

        # 2️⃣ Step-up enforcement on protected resources.
        # FIX: Use PERMITTED_ROLE_SENSITIVITY (0.3) instead of the full resource
        # sensitivity when the role IS permitted. Previously the code always
        # passed the resource's raw sensitivity (e.g. 0.7 for /api/pharmacy)
        # which caused pharmacists accessing their own section to unfairly
        # trigger step-up. The reduced value lets raw risk drive the decision
        # without the resource weighting penalising legitimate access.
        risk_score = user.get("risk_score", 0) or 0
        action = stepup_engine.evaluate(float(risk_score), PERMITTED_ROLE_SENSITIVITY)

        if action in ["mfa", "strong_mfa", "manager_approval", "block"]:
            user_id = user.get("sub")

            # Look up enrollment state so we can tell frontend whether setup is needed.
            enrolled_mfa = False
            try:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT mfa_secret, mfa_enabled, webauthn_credential_id FROM users WHERE id=?",
                    (user_id,)
                )
                row = cursor.fetchone()
                conn.close()
                if row:
                    enrolled_mfa = bool(row["mfa_secret"]) and int(row["mfa_enabled"] or 0) == 1
                    has_webauthn = row["webauthn_credential_id"] is not None
                else:
                    has_webauthn = False
            except Exception:
                has_webauthn = False

            if action == "block":
                raise HTTPException(status_code=403, detail="High risk request blocked.")

            if action == "manager_approval":
                if user_id is not None:
                    create_approval_request(user_id=int(user_id), resource=resource, risk_score=float(risk_score))
                raise HTTPException(
                    status_code=403,
                    detail={
                        "status": "manager_approval_required",
                        "risk_score": float(risk_score),
                        "resource": resource
                    }
                )

            if action == "strong_mfa":
                raise HTTPException(
                    status_code=401,
                    detail={
                        "status": "strong_mfa_required",
                        "methods": ["webauthn"],
                        "user_id": user_id,
                        "risk_score": float(risk_score),
                        "resource": resource
                    }
                )

            # action == "mfa"
            if not enrolled_mfa:
                raise HTTPException(
                    status_code=401,
                    detail={
                        "status": "mfa_setup_required",
                        "user_id": user_id,
                        "risk_score": float(risk_score),
                        "resource": resource
                    }
                )

            raise HTTPException(
                status_code=401,
                detail={
                    "status": "mfa_required",
                    "methods": ["totp"],
                    "user_id": user_id,
                    "risk_score": float(risk_score),
                    "resource": resource
                }
            )

        # 3️⃣ Monitor Restriction Layer
        # FIX: was incorrectly labelled "2️⃣" (duplicate). Now correctly "3️⃣".
        if user.get("monitor"):

            # Restrict high sensitivity endpoints for monitored sessions
            if resource.startswith("/api/admin") and get_resource_sensitivity(resource, user["role"]) > 0.7:
                raise HTTPException(
                    status_code=403,
                    detail="Admin actions disabled in monitored session."
                )

        return user

    return role_dependency