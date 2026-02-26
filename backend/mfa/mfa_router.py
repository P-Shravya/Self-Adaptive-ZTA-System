# backend/mfa/mfa_router.py

from fastapi import APIRouter, HTTPException
from database import get_db_connection
from auth.jwt_utils import create_access_token
from mfa.mfa_utils import generate_secret, generate_qr, verify_totp

router = APIRouter()


@router.post("/mfa/setup")
def setup_mfa(user_id: int):

    secret = generate_secret()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE users SET mfa_secret=?, mfa_enabled=1 WHERE id=?",
                   (secret, user_id))
    conn.commit()
    conn.close()

    qr = generate_qr(str(user_id), secret)

    return {"qr_code_base64": qr}


@router.post("/mfa/verify")
def verify_mfa(user_id: int, otp: str):

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT mfa_secret FROM users WHERE id=?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_totp(row[0], otp):
        raise HTTPException(status_code=401, detail="Invalid OTP")

    token = create_access_token({"sub": user_id})

    return {"access_token": token}