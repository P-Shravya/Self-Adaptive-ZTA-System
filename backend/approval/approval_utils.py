# backend/approval/approval_utils.py

from datetime import datetime, timedelta
from backend.database import get_db

APPROVAL_VALIDITY_MINUTES = 60


# ==========================================================
# 🔹 CREATE APPROVAL REQUEST (PENDING)
# ==========================================================
def create_approval_request(user_id: int, resource: str, risk_score: float):

    db = get_db()
    cursor = db.cursor()

    # Prevent duplicate active requests
    existing = cursor.execute("""
        SELECT id FROM approval_requests
        WHERE user_id=? AND resource=?
    """, (user_id, resource)).fetchone()

    if existing:
        db.close()
        return

    cursor.execute("""
        INSERT INTO approval_requests
        (user_id, resource, risk_score, requested_at)
        VALUES (?, ?, ?, ?)
    """, (
        user_id,
        resource,
        risk_score,
        datetime.utcnow().isoformat()
    ))

    db.commit()
    db.close()


# ==========================================================
# 🔹 APPROVE REQUEST
#    - Only valid if within 60 minutes
#    - Move to approval_logs
#    - Remove from approval_requests
# ==========================================================
def approve_request(request_id: int, decided_by: str):

    db = get_db()
    cursor = db.cursor()

    #1️⃣ Fetch Pending Request
    request = cursor.execute("""
        SELECT * FROM approval_requests
        WHERE id=?
    """, (request_id,)).fetchone()

    if not request:
        db.close()
        return {"status": "not_found"}

    requested_time = datetime.fromisoformat(request["requested_at"])

    # Expiry enforcement
    if datetime.utcnow() - requested_time > timedelta(minutes=APPROVAL_VALIDITY_MINUTES):
        # Delete expired request
        cursor.execute("""
            DELETE FROM approval_requests WHERE id=?
        """, (request_id,))
        db.commit()
        db.close()
        return {"status": "expired"}

    #2️⃣ Fetch latest behavior log for forensic context
    latest_log = cursor.execute("""
        SELECT session_id, ip_address, location_country, device_id
        FROM behavior_logs
        WHERE user_id=?
        ORDER BY timestamp DESC
        LIMIT 1
    """, (request["user_id"],)).fetchone()

    #3️⃣ Insert into approval_logs
    cursor.execute("""
        INSERT INTO approval_logs
        (
            user_id,
            resource,
            risk_score,
            decision,
            decided_by,
            decided_at,
            session_id,
            ip_address,
            geo_location,
            device_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        request["user_id"],
        request["resource"],
        request["risk_score"],
        "approved",
        decided_by,
        datetime.utcnow().isoformat(),
        latest_log["session_id"] if latest_log else None,
        latest_log["ip_address"] if latest_log else None,
        latest_log["location_country"] if latest_log else None,
        latest_log["device_id"] if latest_log else None
    ))

    #4️⃣ Delete from pending table
    cursor.execute("""
        DELETE FROM approval_requests WHERE id=?
    """, (request_id,))

    db.commit()
    db.close()

    return {"status": "approved"}


# ==========================================================
# 🔹 REJECT REQUEST
#    - Same expiry enforcement
# ==========================================================
def reject_request(request_id: int, decided_by: str):

    db = get_db()
    cursor = db.cursor()
    
    #1️⃣ Fetch Pending Request
    request = cursor.execute("""
        SELECT * FROM approval_requests
        WHERE id=?
    """, (request_id,)).fetchone()

    if not request:
        db.close()
        return {"status": "not_found"}

    requested_time = datetime.fromisoformat(request["requested_at"])

    # Expiry enforcement
    if datetime.utcnow() - requested_time > timedelta(minutes=APPROVAL_VALIDITY_MINUTES):
        cursor.execute("""
            DELETE FROM approval_requests WHERE id=?
        """, (request_id,))
        db.commit()
        db.close()
        return {"status": "expired"}
    
    #2️⃣ Fetch latest behavior log for forensic context
    latest_log = cursor.execute("""
        SELECT session_id, ip_address, location_country, device_id
        FROM behavior_logs
        WHERE user_id=?
        ORDER BY timestamp DESC
        LIMIT 1
    """, (request["user_id"],)).fetchone()

    #3️⃣ Insert into approval_logs
    cursor.execute("""
        INSERT INTO approval_logs
        (
            user_id,
            resource,
            risk_score,
            decision,
            decided_by,
            decided_at,
            session_id,
            ip_address,
            geo_location,
            device_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        request["user_id"],
        request["resource"],
        request["risk_score"],
        "rejected",
        decided_by,
        datetime.utcnow().isoformat(),
        latest_log["session_id"] if latest_log else None,
        latest_log["ip_address"] if latest_log else None,
        latest_log["location_country"] if latest_log else None,
        latest_log["device_id"] if latest_log else None
    ))

    #4️⃣ Delete from pending table
    cursor.execute("""
        DELETE FROM approval_requests WHERE id=?
    """, (request_id,))

    db.commit()
    db.close()

    return {"status": "rejected"}