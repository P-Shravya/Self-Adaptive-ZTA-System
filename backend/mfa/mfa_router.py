# backend/mfa/mfa_router.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from backend.database import get_db
from backend.auth.jwt_utils import create_token
from backend.mfa.mfa_utils import generate_secret, generate_qr, verify_totp

router = APIRouter()

class SetupBody(BaseModel):
    user_id: int

class VerifyBody(BaseModel):
    user_id: int
    otp: str
    risk_score: float = 0.0   # FIX: accept risk_score from frontend so it can
                               # be preserved in the post-MFA token. Frontend
                               # should read this from the login response or
                               # localStorage and pass it here.


@router.post("/mfa/setup")
def setup_mfa(body: SetupBody):
    user_id = body.user_id

    conn = get_db()
    cursor = conn.cursor()

    # Check if MFA already enabled
    cursor.execute(
        "SELECT mfa_secret FROM users WHERE id=?",
        (user_id,)
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    # If secret already exists, reuse it
    if row["mfa_secret"]:
        secret = row["mfa_secret"]

    else:
        secret = generate_secret()

        cursor.execute(
            "UPDATE users SET mfa_secret=?, mfa_enabled=1 WHERE id=?",
            (secret, user_id)
        )
        conn.commit()

    conn.close()

    qr = generate_qr(str(user_id), secret)

    return {"qr_code_base64": qr}

@router.post("/mfa/verify")
def verify_mfa(body: VerifyBody):
    user_id = body.user_id
    otp = body.otp

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT username, role, mfa_secret FROM users WHERE id=?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_totp(row["mfa_secret"], otp):
        raise HTTPException(status_code=401, detail="Invalid OTP")

    # FIX: preserve risk_score in the post-MFA token.
    # Previously create_token() was called without risk_score, so the new JWT
    # had risk_score=None, making the user appear risk-free after MFA and
    # bypassing all subsequent step-up checks in require_role_access().
    token = create_token({
        "sub": user_id,
        "username": row["username"],
        "role": row["role"],
        "mfa": True,
        "risk_score": body.risk_score   # FIX: carry the original risk score forward
    })

    return {"access_token": token}