# backend/security/approval_middleware.py

"""
This middleware enforces manager approval for high-sensitivity resources.

It ensures:

1️⃣ If approval request is still pending → user must wait.
2️⃣ If approval request expired (> 60 minutes) → auto-delete + force re-login.
3️⃣ If approved → allow access (only if approval is within 60 minutes).
4️⃣ If rejected or no approval → deny access.

This implements time-bound Zero Trust approval enforcement.
"""

from datetime import datetime, timedelta
from fastapi import Depends, HTTPException
from backend.database import get_db
from backend.security.auth_dependencies import get_current_user


# 🔹 Approval validity window (in minutes)
# User must be approved within this time.
APPROVAL_VALIDITY_MINUTES = 60


def require_approval(resource: str):
    """
    This function returns a dependency that protects a specific resource.

    Example usage:
        @router.get("/admin")
        def admin_dashboard(user=Depends(require_approval("/api/admin"))):

    It ensures that the user accessing this resource:
        - Has manager approval
        - Approval is not expired
        - No pending approval is stuck
    """

    def approval_dependency(user=Depends(get_current_user)):
        """
        This inner function executes every time
        a protected endpoint is accessed.
        """

        db = get_db()
        cursor = db.cursor()

        # ==========================================================
        # 1️⃣ CHECK IF A PENDING REQUEST EXISTS
        # ==========================================================
        pending = cursor.execute("""
            SELECT *
            FROM approval_requests
            WHERE user_id=? AND resource=?
        """, (user["sub"], resource)).fetchone()

        if pending:
            requested_time = datetime.fromisoformat(pending["requested_at"])

            # 🔴 If pending request is older than 60 minutes → expire it
            if datetime.utcnow() - requested_time > timedelta(minutes=APPROVAL_VALIDITY_MINUTES):

                # Auto-delete expired request
                cursor.execute("""
                    DELETE FROM approval_requests
                    WHERE id=?
                """, (pending["id"],))
                db.commit()
                db.close()

                # Force user to re-login
                raise HTTPException(
                    status_code=403,
                    detail="Approval request expired. Please re-login."
                )

            # 🟡 If still within 60 minutes → still waiting
            db.close()
            raise HTTPException(
                status_code=403,
                detail="Waiting for manager approval."
            )

        # ==========================================================
        # 2️⃣ CHECK IF APPROVAL EXISTS IN APPROVAL LOGS
        # ==========================================================
        approval = cursor.execute("""
            SELECT *
            FROM approval_logs
            WHERE user_id=?
              AND resource=?
              AND decision='approved'
            ORDER BY decided_at DESC
            LIMIT 1
        """, (user["sub"], resource)).fetchone()

        db.close()

        # 🔴 No approval found
        if not approval:
            raise HTTPException(
                status_code=403,
                detail="Manager approval required."
            )

        # ==========================================================
        # 3️⃣ CHECK IF APPROVAL HAS EXPIRED
        # ==========================================================
        decided_time = datetime.fromisoformat(approval["decided_at"])

        if datetime.utcnow() - decided_time > timedelta(minutes=APPROVAL_VALIDITY_MINUTES):
            raise HTTPException(
                status_code=403,
                detail="Approval expired. Please re-login."
            )

        # ==========================================================
        # 4️⃣ ALL CONDITIONS PASSED → ALLOW ACCESS
        # ==========================================================
        return user

    return approval_dependency