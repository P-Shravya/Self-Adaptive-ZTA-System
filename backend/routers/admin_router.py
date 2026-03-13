from fastapi import APIRouter, Depends
from backend.security.auth_dependencies import require_role_access

router = APIRouter(prefix="/api/admin", tags=["Admin"])

@router.get("/dashboard")
def admin_dashboard(
    user=Depends(require_role_access("/api/admin"))
):
    return {"message": "Admin Dashboard"}