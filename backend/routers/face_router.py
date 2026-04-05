# backend/routers/face_router.py
# Face Authentication - triggered when risk score is in medium range (31-70)
# Uses stored face descriptor vectors compared client-side via face-api.js
# Backend stores/retrieves the descriptor and logs the verification event

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from backend.database import get_db
from backend.security.auth_dependencies import get_current_user

router = APIRouter(prefix="/api/face", tags=["Face Auth"])


class FaceEnrollRequest(BaseModel):
    user_id: int
    descriptor: List[float]   # 128-float face descriptor from face-api.js


class FaceVerifyRequest(BaseModel):
    user_id: int
    descriptor: List[float]   # 128-float face descriptor to compare


class FaceVerifyLoginRequest(BaseModel):
    """Used during login step-up (no token yet)"""
    user_id: int
    descriptor: List[float]


# ============================================================
# 🔹 ENROLL FACE (authenticated users only)
# ============================================================
@router.post("/enroll")
def enroll_face(data: FaceEnrollRequest, user=Depends(get_current_user)):
    """
    Store the face descriptor for a user.
    The descriptor is a 128-float array from face-api.js FaceNet model.
    """
    import json

    # Only allow users to enroll their own face
    if str(user.get("sub")) != str(data.user_id):
        raise HTTPException(status_code=403, detail="Cannot enroll face for another user")

    if len(data.descriptor) != 128:
        raise HTTPException(status_code=400, detail="Invalid face descriptor: expected 128 floats")

    descriptor_json = json.dumps(data.descriptor)

    db = get_db()
    cursor = db.cursor()

    # Ensure face_auth table exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS face_auth (
            user_id     INTEGER PRIMARY KEY,
            descriptor  TEXT NOT NULL,
            enrolled_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        INSERT INTO face_auth (user_id, descriptor, enrolled_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            descriptor  = excluded.descriptor,
            enrolled_at = excluded.enrolled_at
    """, (data.user_id, descriptor_json, datetime.utcnow().isoformat()))

    db.commit()
    db.close()

    return {"status": "enrolled", "message": "Face enrolled successfully"}


# ============================================================
# 🔹 GET ENROLLED DESCRIPTOR (for client-side comparison)
# ============================================================
@router.get("/descriptor/{user_id}")
def get_descriptor(user_id: int):
    """
    Return the stored face descriptor for client-side comparison.
    face-api.js performs the Euclidean distance check in the browser.
    """
    import json

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS face_auth (
            user_id     INTEGER PRIMARY KEY,
            descriptor  TEXT NOT NULL,
            enrolled_at TEXT NOT NULL
        )
    """)

    row = cursor.execute(
        "SELECT descriptor, enrolled_at FROM face_auth WHERE user_id=?",
        (user_id,)
    ).fetchone()
    db.close()

    if not row:
        raise HTTPException(status_code=404, detail="No face enrolled for this user")

    return {
        "user_id": user_id,
        "descriptor": json.loads(row["descriptor"]),
        "enrolled_at": row["enrolled_at"]
    }


# ============================================================
# 🔹 LOG FACE VERIFICATION RESULT (called after client-side match)
# ============================================================
@router.post("/verify-result")
def log_face_result(data: FaceVerifyLoginRequest):
    """
    Client sends result after performing face comparison.
    Backend logs the event and returns a step-up token if passed.
    """
    from backend.auth.jwt_utils import create_token
    import json

    db = get_db()
    cursor = db.cursor()

    # Ensure table exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS face_auth (
            user_id     INTEGER PRIMARY KEY,
            descriptor  TEXT NOT NULL,
            enrolled_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS face_auth_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            verified    INTEGER NOT NULL,
            distance    REAL,
            timestamp   TEXT NOT NULL
        )
    """)

    row = cursor.execute(
        "SELECT descriptor FROM face_auth WHERE user_id=?",
        (data.user_id,)
    ).fetchone()

    if not row:
        db.close()
        raise HTTPException(status_code=404, detail="No face enrolled for this user. Please enroll first.")

    stored = json.loads(row["descriptor"])

    # Compute Euclidean distance server-side as confirmation
    import math
    if len(data.descriptor) != 128:
        db.close()
        raise HTTPException(status_code=400, detail="Invalid descriptor length")

    distance = math.sqrt(sum((a - b) ** 2 for a, b in zip(stored, data.descriptor)))
    THRESHOLD = 0.6   # face-api.js default threshold
    verified = distance <= THRESHOLD

    # Log it
    cursor.execute("""
        INSERT INTO face_auth_logs (user_id, verified, distance, timestamp)
        VALUES (?, ?, ?, ?)
    """, (data.user_id, int(verified), round(distance, 4), datetime.utcnow().isoformat()))
    db.commit()

    if not verified:
        db.close()
        raise HTTPException(status_code=401, detail=f"Face verification failed (distance: {round(distance,3)})")

    # Build a face-verified token
    user_row = cursor.execute(
        "SELECT id, username, role FROM users WHERE id=?",
        (data.user_id,)
    ).fetchone()
    db.close()

    if not user_row:
        raise HTTPException(status_code=404, detail="User not found")

    token = create_token({
        "sub": user_row["id"],
        "username": user_row["username"],
        "role": user_row["role"],
        "face_verified": True,
        "risk_score": 0
    })

    return {
        "status": "verified",
        "distance": round(distance, 4),
        "access_token": token,
        "token_type": "bearer",
        "message": "Face authentication successful"
    }


# ============================================================
# 🔹 CHECK ENROLLMENT STATUS
# ============================================================
@router.get("/status/{user_id}")
def face_status(user_id: int):
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS face_auth (
            user_id     INTEGER PRIMARY KEY,
            descriptor  TEXT NOT NULL,
            enrolled_at TEXT NOT NULL
        )
    """)

    row = cursor.execute(
        "SELECT enrolled_at FROM face_auth WHERE user_id=?",
        (user_id,)
    ).fetchone()
    db.close()

    return {
        "enrolled": row is not None,
        "enrolled_at": row["enrolled_at"] if row else None
    }
