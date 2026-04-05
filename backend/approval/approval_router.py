# backend/approval/approval_router.py

from fastapi import APIRouter, Depends, HTTPException
from backend.database import get_db
from backend.auth.jwt_utils import create_token
from backend.approval.approval_utils import (
    approve_request,
    reject_request
)
from backend.security.auth_dependencies import (
    get_current_user,
    require_manager
)

router = APIRouter(
    prefix="/api/approvals",
    tags=["Approvals"]
)


# ==========================================================
# 🔹 GET PENDING REQUESTS (Managers Only)
# ==========================================================
@router.get("/pending")
def get_pending_requests(user=Depends(require_manager)):

    db = get_db()
    cursor = db.cursor()

    requests = cursor.execute("""
        SELECT ar.id,
               ar.user_id,
               u.username,
               ar.resource,
               ar.risk_score,
               ar.requested_at
        FROM approval_requests ar
        JOIN users u ON ar.user_id = u.id
        ORDER BY ar.requested_at DESC
    """).fetchall()

    db.close()

    return {"pending_requests": [dict(r) for r in requests]}


# ==========================================================
# 🔹 APPROVE REQUEST (Managers Only)
# ==========================================================
@router.post("/{request_id}/approve")
def approve(
    request_id: int,
    user=Depends(require_manager)
):

    result = approve_request(request_id, user["username"])

    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail="Request not found")

    return {"message": "Request approved successfully"}


# ==========================================================
# 🔹 REJECT REQUEST (Managers Only)
# ==========================================================
@router.post("/{request_id}/reject")
def reject(
    request_id: int,
    user=Depends(require_manager)
):

    result = reject_request(request_id, user["username"])

    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail="Request not found")

    return {"message": "Request rejected successfully"}


# ==========================================================
# 🔹 GET APPROVAL HISTORY (Managers Only)
# ==========================================================
@router.get("/history")
def get_approval_history(user=Depends(require_manager)):

    db = get_db()
    cursor = db.cursor()

    logs = cursor.execute("""
        SELECT *
        FROM approval_logs
        ORDER BY decided_at DESC
    """).fetchall()

    db.close()

    return {"approval_history": [dict(r) for r in logs]}


@router.get("/status")
def get_approval_status(user=Depends(get_current_user)):
    db = get_db()
    cursor = db.cursor()

    try:
        user_id = int(user["sub"])

        pending = cursor.execute("""
            SELECT requested_at FROM approval_requests
            WHERE user_id=?
            ORDER BY requested_at DESC LIMIT 1
        """, (user_id,)).fetchone()

        if pending:
            from datetime import datetime, timedelta

            age = datetime.utcnow() - datetime.fromisoformat(pending["requested_at"])
            if age > timedelta(minutes=60):
                return {"status": "expired"}

            return {"status": "pending"}

        log = cursor.execute("""
            SELECT decision FROM approval_logs
            WHERE user_id=?
            ORDER BY decided_at DESC LIMIT 1
        """, (user_id,)).fetchone()

        if not log:
            return {"status": "pending"}

        decision = str(log["decision"])
        if decision != "approved":
            return {"status": decision}

        urow = cursor.execute(
            "SELECT username, role FROM users WHERE id=?",
            (user_id,),
        ).fetchone()
        if not urow:
            raise HTTPException(status_code=404, detail="User not found")

        risk = float(user.get("risk_score", 0) or 0)
        new_token = create_token(
            {
                "sub": user_id,
                "username": urow["username"],
                "role": urow["role"],
                "risk_score": risk,
            }
        )
        return {
            "status": "approved",
            "access_token": new_token,
            "token_type": "bearer",
        }
    finally:
        db.close()