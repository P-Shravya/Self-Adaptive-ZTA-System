from fastapi import APIRouter, Depends
from backend.security.auth_dependencies import require_role_access

router = APIRouter(prefix="/api/pharmacy", tags=["Pharmacy"])

@router.get("/")
def pharmacy_section(
    user=Depends(require_role_access("/api/pharmacy"))
):
    return {"message": "Pharmacy Section"}