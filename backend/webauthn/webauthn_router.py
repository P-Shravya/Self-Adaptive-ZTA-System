# backend/webauthn/webauthn_router.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from backend.database import get_db
from backend.auth.jwt_utils import create_token
from backend.webauthn.webauthn_utils import (
    create_registration_options,
    verify_registration,
    create_authentication_options,
    verify_authentication,
)

router = APIRouter()


class OptionsBody(BaseModel):
    user_id: int


class RegisterVerifyBody(BaseModel):
    user_id: int
    id: str
    rawId: str
    type: str
    response: dict


class AuthenticateVerifyBody(BaseModel):
    user_id: int
    id: str
    rawId: str
    type: str
    response: dict


# ──────────────────────────────────────────────
#  REGISTER: Step 1 — Generate options
#  BUG 4 FIX: store challenge in DB
# ──────────────────────────────────────────────
@router.post("/webauthn/register-options")
def register_options(body: OptionsBody):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT username FROM users WHERE id=?", (body.user_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    # BUG 3+4 FIX: get JSON-serializable dict + challenge bytes
    options_dict, challenge_bytes = create_registration_options(body.user_id, row["username"])

    # BUG 4 FIX: store challenge server-side for verification
    cursor.execute(
        "UPDATE users SET webauthn_challenge=? WHERE id=?",
        (challenge_bytes, body.user_id)
    )
    conn.commit()
    conn.close()

    return options_dict


# ──────────────────────────────────────────────
#  REGISTER: Step 2 — Verify attestation
#  BUG 4 FIX: use server-stored challenge
# ──────────────────────────────────────────────
@router.post("/webauthn/register-verify")
def register_verify(body: RegisterVerifyBody):
    conn = get_db()
    cursor = conn.cursor()

    # BUG 4 FIX: fetch server-stored challenge
    cursor.execute(
        "SELECT webauthn_challenge FROM users WHERE id=?",
        (body.user_id,)
    )
    row = cursor.fetchone()
    if not row or not row["webauthn_challenge"]:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="No pending registration challenge. Call /webauthn/register-options first."
        )

    expected_challenge = bytes(row["webauthn_challenge"])

    credentials = body.model_dump(exclude={"user_id"})
    verification = verify_registration(credentials, expected_challenge)

    # Save credential, clear used challenge
    cursor.execute("""
        UPDATE users SET
            webauthn_credential_id = ?,
            webauthn_public_key    = ?,
            webauthn_sign_count    = ?,
            webauthn_challenge     = NULL
        WHERE id = ?
    """, (
        verification.credential_id,
        verification.credential_public_key,
        verification.sign_count,
        body.user_id,
    ))
    conn.commit()
    conn.close()

    return {"status": "registered"}


# ──────────────────────────────────────────────
#  AUTHENTICATE: Step 1 — Generate options
#  BUG 4+6 FIX: store challenge, pass bytes
# ──────────────────────────────────────────────
@router.post("/webauthn/authenticate-options")
def authenticate_options(body: OptionsBody):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT webauthn_credential_id FROM users WHERE id=?",
        (body.user_id,)
    )
    row = cursor.fetchone()
    if not row or not row["webauthn_credential_id"]:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="No WebAuthn device registered for this user. Please register first."
        )

    # BUG 6 FIX: ensure bytes from BLOB column
    credential_id_bytes = bytes(row["webauthn_credential_id"])

    # BUG 3+4 FIX: get JSON-safe dict + server challenge bytes
    options_dict, challenge_bytes = create_authentication_options(credential_id_bytes)

    # BUG 4 FIX: store challenge server-side
    cursor.execute(
        "UPDATE users SET webauthn_challenge=? WHERE id=?",
        (challenge_bytes, body.user_id)
    )
    conn.commit()
    conn.close()

    return options_dict


# ──────────────────────────────────────────────
#  AUTHENTICATE: Step 2 — Verify assertion
#  BUG 4 FIX: use server-stored challenge
# ──────────────────────────────────────────────
@router.post("/webauthn/authenticate-verify")
def authenticate_verify(body: AuthenticateVerifyBody):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT webauthn_public_key, webauthn_sign_count,
               webauthn_challenge, username, role
        FROM users WHERE id=?
    """, (body.user_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found.")

    if not row["webauthn_challenge"]:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="No pending authentication challenge. Call /webauthn/authenticate-options first."
        )

    # BUG 4 FIX: use stored server-side challenge bytes
    expected_challenge = bytes(row["webauthn_challenge"])
    public_key_bytes   = bytes(row["webauthn_public_key"])

    credentials = body.model_dump(exclude={"user_id"})
    verification = verify_authentication(
        credentials,
        expected_challenge,
        public_key_bytes,
        row["webauthn_sign_count"],
    )

    # Update sign count, clear used challenge
    cursor.execute(
        "UPDATE users SET webauthn_sign_count=?, webauthn_challenge=NULL WHERE id=?",
        (verification.new_sign_count, body.user_id)
    )
    conn.commit()

    cursor.execute("SELECT username, role FROM users WHERE id=?", (body.user_id,))
    user_row = cursor.fetchone()
    conn.close()

    token = create_token({
        "sub": body.user_id,
        "username": user_row["username"],
        "role": user_row["role"],
        "webauthn": True,
    })

    return {"status": "verified", "access_token": token}