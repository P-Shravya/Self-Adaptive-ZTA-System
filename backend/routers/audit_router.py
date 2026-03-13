# backend/routers/audit_router.py
# Audit Log - admin/manager only endpoint
# Returns paginated behavior_logs + approval_logs + face_auth_logs

from fastapi import APIRouter, Depends, Query
from backend.database import get_db
from backend.security.auth_dependencies import require_manager

router = APIRouter(prefix="/api/audit", tags=["Audit"])


@router.get("/logs")
def get_audit_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    user_id: int = Query(None),
    action: str = Query(None),
    user=Depends(require_manager)
):
    """
    Paginated audit log of all behavior events.
    Accessible by admin and manager roles only.
    """
    db = get_db()
    cursor = db.cursor()
    offset = (page - 1) * limit

    filters = []
    params = []

    if user_id:
        filters.append("bl.user_id = ?")
        params.append(user_id)
    if action:
        filters.append("bl.action LIKE ?")
        params.append(f"%{action}%")

    where_clause = ("WHERE " + " AND ".join(filters)) if filters else ""

    rows = cursor.execute(f"""
        SELECT
            bl.id,
            bl.user_id,
            bl.username,
            bl.timestamp,
            bl.ip_address,
            bl.location_country,
            bl.device_type,
            bl.os,
            bl.browser,
            bl.resource,
            bl.action,
            bl.vpn_detected,
            bl.proxy_detected,
            bl.failed_attempts,
            bl.session_id,
            u.role
        FROM behavior_logs bl
        LEFT JOIN users u ON bl.user_id = u.id
        {where_clause}
        ORDER BY bl.timestamp DESC
        LIMIT ? OFFSET ?
    """, params + [limit, offset]).fetchall()

    total = cursor.execute(f"""
        SELECT COUNT(*) as cnt FROM behavior_logs bl
        LEFT JOIN users u ON bl.user_id = u.id
        {where_clause}
    """, params).fetchone()["cnt"]

    db.close()

    return {
        "logs": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit
    }


@router.get("/approval-logs")
def get_approval_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    user=Depends(require_manager)
):
    """Paginated approval decision history."""
    db = get_db()
    cursor = db.cursor()
    offset = (page - 1) * limit

    rows = cursor.execute("""
        SELECT
            al.id,
            al.user_id,
            u.username,
            al.resource,
            al.risk_score,
            al.decision,
            al.decided_by,
            al.decided_at,
            al.ip_address,
            u.role
        FROM approval_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.decided_at DESC
        LIMIT ? OFFSET ?
    """, [limit, offset]).fetchall()

    total = cursor.execute("SELECT COUNT(*) as cnt FROM approval_logs").fetchone()["cnt"]
    db.close()

    return {
        "logs": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "limit": limit
    }


@router.get("/face-logs")
def get_face_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    user=Depends(require_manager)
):
    """Face authentication attempt history."""
    db = get_db()
    cursor = db.cursor()
    offset = (page - 1) * limit

    # Create table if not yet created
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS face_auth_logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER NOT NULL,
            verified  INTEGER NOT NULL,
            distance  REAL,
            timestamp TEXT NOT NULL
        )
    """)

    rows = cursor.execute("""
        SELECT
            fl.id,
            fl.user_id,
            u.username,
            u.role,
            fl.verified,
            fl.distance,
            fl.timestamp
        FROM face_auth_logs fl
        LEFT JOIN users u ON fl.user_id = u.id
        ORDER BY fl.timestamp DESC
        LIMIT ? OFFSET ?
    """, [limit, offset]).fetchall()

    total = cursor.execute("SELECT COUNT(*) as cnt FROM face_auth_logs").fetchone()["cnt"]
    db.close()

    return {
        "logs": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "limit": limit
    }


@router.get("/stats")
def get_audit_stats(user=Depends(require_manager)):
    """High-level stats for the audit dashboard header."""
    db = get_db()
    cursor = db.cursor()

    total_events   = cursor.execute("SELECT COUNT(*) as c FROM behavior_logs").fetchone()["c"]
    failed_logins  = cursor.execute("SELECT COUNT(*) as c FROM behavior_logs WHERE action='login_failed'").fetchone()["c"]
    vpn_detected   = cursor.execute("SELECT COUNT(*) as c FROM behavior_logs WHERE vpn_detected=1").fetchone()["c"]
    blocked        = cursor.execute("SELECT COUNT(*) as c FROM approval_logs WHERE decision='rejected'").fetchone()["c"]
    approved       = cursor.execute("SELECT COUNT(*) as c FROM approval_logs WHERE decision='approved'").fetchone()["c"]

    # Face auth stats (table may not exist yet)
    try:
        cursor.execute("CREATE TABLE IF NOT EXISTS face_auth_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, verified INTEGER, distance REAL, timestamp TEXT)")
        face_pass = cursor.execute("SELECT COUNT(*) as c FROM face_auth_logs WHERE verified=1").fetchone()["c"]
        face_fail = cursor.execute("SELECT COUNT(*) as c FROM face_auth_logs WHERE verified=0").fetchone()["c"]
    except Exception:
        face_pass = face_fail = 0

    db.close()

    return {
        "total_events":  total_events,
        "failed_logins": failed_logins,
        "vpn_detected":  vpn_detected,
        "blocked":       blocked,
        "approved":      approved,
        "face_pass":     face_pass,
        "face_fail":     face_fail
    }
