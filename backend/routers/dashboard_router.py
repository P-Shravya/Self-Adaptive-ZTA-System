from fastapi import APIRouter, Depends
from backend.security.auth_dependencies import require_role_access

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/")
def dashboard_home(
    user=Depends(require_role_access("/api/dashboard"))
):
    return {"message": f"{user['role']} Dashboard"}