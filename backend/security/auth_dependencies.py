# backend/security/auth_dependencies.py

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from backend.auth.jwt_utils import verify_token

from backend.security.resource_policy import has_access


security = HTTPBearer()


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

        if not has_access(user.get("role"), resource):
            raise HTTPException(
                status_code=403,
                detail="Access denied for your role."
            )

        return user

    return role_dependency
