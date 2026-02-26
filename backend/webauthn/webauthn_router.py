# backend/webauthn/webauthn_router.py

from fastapi import APIRouter, HTTPException
from backend.database import get_db
from webauthn.webauthn_utils import (
    create_registration_options,
    verify_registration,
    create_authentication_options,
    verify_authentication
)

router = APIRouter()


@router.post("/webauthn/register-options")
def register_options(user_id: int, username: str):

    options = create_registration_options(user_id, username)
    return options


@router.post("/webauthn/register-verify")
def register_verify(user_id: int, credentials: dict):

    verification = verify_registration(credentials, credentials["response"]["clientDataJSON"])

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users SET 
        webauthn_credential_id=?,
        webauthn_public_key=?,
        webauthn_sign_count=?
        WHERE id=?
    """, (
        verification.credential_id,
        verification.credential_public_key,
        verification.sign_count,
        user_id
    ))

    conn.commit()
    conn.close()

    return {"status": "registered"}


@router.post("/webauthn/authenticate-options")
def authenticate_options(user_id: int):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT webauthn_credential_id FROM users WHERE id=?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="No WebAuthn credential")

    return create_authentication_options(row["webauthn_credential_id"])


@router.post("/webauthn/authenticate-verify")
def authenticate_verify(user_id: int, credentials: dict):

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT webauthn_public_key, webauthn_sign_count 
        FROM users WHERE id=?
    """, (user_id,))
    row = cursor.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Credential not found")

    verification = verify_authentication(
        credentials,
        credentials["response"]["clientDataJSON"],
        row["webauthn_public_key"],
        row["webauthn_sign_count"]
    )

    cursor.execute(
        "UPDATE users SET webauthn_sign_count=? WHERE id=?",
        (verification.new_sign_count, user_id)
    )

    conn.commit()
    conn.close()

    return {"status": "verified"}