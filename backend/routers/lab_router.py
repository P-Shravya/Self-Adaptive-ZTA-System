from fastapi import APIRouter, Depends
from backend.security.auth_dependencies import require_role_access

router = APIRouter(prefix="/api/lab", tags=["Lab"])

@router.get("/")
def lab_section(
    user=Depends(require_role_access("/api/lab"))
):
    return {"message": "Lab Section"}