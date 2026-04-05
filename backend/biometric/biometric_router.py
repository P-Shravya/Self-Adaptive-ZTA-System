# backend/biometric/biometric_router.py

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from backend.auth.jwt_utils import create_token
from backend.auth.jwt_utils import verify_token
from backend.database import get_db
from backend.biometric.biometric_utils import (
    create_registration_options,
    verify_registration,
    create_authentication_options,
    verify_authentication,
)

router = APIRouter()

class OptionsBody(BaseModel):
    user_id: int
    # Used during login strong-mfa flow.
    mfa_context_token: str | None = None


class StatusBody(BaseModel):
    user_id: int
    mfa_context_token: str | None = None


class RegisterVerifyBody(BaseModel):
    user_id: int
    mfa_context_token: str | None = None
    id: str
    rawId: str
    type: str
    response: dict


class AuthenticateVerifyBody(BaseModel):
    user_id: int
    mfa_context_token: str | None = None
    id: str
    rawId: str
    type: str
    response: dict


def _authorization_from_request(request: Request) -> str | None:
    return request.headers.get("Authorization") or request.headers.get("authorization")


def _normalize_jwt_string(raw: str | None) -> str | None:
    if not raw:
        return None
    s = raw.strip()
    if not s:
        return None
    if s.lower().startswith("bearer "):
        s = s[7:].strip()
    return s or None


def _jwt_candidates(request: Request, body_token: str | None) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for part in (
        _normalize_jwt_string(body_token),
        _normalize_jwt_string(_authorization_from_request(request)),
    ):
        if part and part not in seen:
            seen.add(part)
            out.append(part)
    return out


def _resolve_mfa_context(request: Request, body_token: str | None) -> dict:
    last_err = "Missing biometric MFA token."
    for jwt_str in _jwt_candidates(request, body_token):
        payload = verify_token(jwt_str)
        if not payload:
            last_err = "Invalid or expired biometric MFA token."
            continue
        if payload.get("sub") is None:
            last_err = "Invalid biometric MFA token context."
            continue
        return payload
    raise HTTPException(status_code=401, detail=last_err)


def _assert_token_user_match(context: dict, user_id: int) -> None:
    token_user_id = int(context.get("sub"))
    if token_user_id != int(user_id):
        raise HTTPException(status_code=403, detail="Biometric token does not match user_id.")


@router.post("/biometric/register-options")
def register_options(request: Request, body: OptionsBody):
    context = _resolve_mfa_context(request, body.mfa_context_token)
    _assert_token_user_match(context, body.user_id)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT username FROM users WHERE id=?", (body.user_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    # Allow registration only once.
    existing_credential = cursor.execute(
        "SELECT biometric_credential_id FROM users WHERE id=?",
        (body.user_id,),
    ).fetchone()
    if existing_credential and existing_credential["biometric_credential_id"] is not None:
        conn.close()
        raise HTTPException(status_code=409, detail="Biometric is already registered for this user.")

    options_dict, challenge_bytes = create_registration_options(body.user_id, row["username"])
    cursor.execute(
        "UPDATE users SET biometric_challenge=? WHERE id=?",
        (challenge_bytes, body.user_id),
    )
    conn.commit()
    conn.close()
    return options_dict


@router.post("/biometric/register-verify")
def register_verify(request: Request, body: RegisterVerifyBody):
    context = _resolve_mfa_context(request, body.mfa_context_token)
    _assert_token_user_match(context, body.user_id)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT biometric_challenge FROM users WHERE id=?",
        (body.user_id,),
    )
    row = cursor.fetchone()
    if not row or not row["biometric_challenge"]:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="No pending biometric registration challenge. Call /biometric/register-options first.",
        )

    # Prevent re-enrollment.
    credential_row = cursor.execute(
        "SELECT biometric_credential_id FROM users WHERE id=?",
        (body.user_id,),
    ).fetchone()
    if credential_row and credential_row["biometric_credential_id"] is not None:
        conn.close()
        raise HTTPException(status_code=409, detail="Biometric is already registered for this user.")

    expected_challenge = bytes(row["biometric_challenge"])
    credentials = body.model_dump(exclude={"user_id", "mfa_context_token"})
    verification = verify_registration(credentials, expected_challenge)

    cursor.execute(
        """
        UPDATE users SET
            biometric_credential_id = ?,
            biometric_public_key    = ?,
            biometric_sign_count    = ?,
            biometric_challenge     = NULL
        WHERE id = ?
        """,
        (
            verification.credential_id,
            verification.credential_public_key,
            verification.sign_count,
            body.user_id,
        ),
    )
    conn.commit()
    conn.close()
    return {"status": "registered"}


@router.post("/biometric/authenticate-options")
def authenticate_options(request: Request, body: OptionsBody):
    context = _resolve_mfa_context(request, body.mfa_context_token)
    _assert_token_user_match(context, body.user_id)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT biometric_credential_id FROM users WHERE id=?",
        (body.user_id,),
    )
    row = cursor.fetchone()
    if not row or not row["biometric_credential_id"]:
        conn.close()
        raise HTTPException(
            status_code=404,
            detail="No biometric device registered for this user. Please register first.",
        )

    credential_id_bytes = bytes(row["biometric_credential_id"])
    options_dict, challenge_bytes = create_authentication_options(credential_id_bytes)

    cursor.execute(
        "UPDATE users SET biometric_challenge=? WHERE id=?",
        (challenge_bytes, body.user_id),
    )
    conn.commit()
    conn.close()
    return options_dict


@router.post("/biometric/authenticate-verify")
def authenticate_verify(request: Request, body: AuthenticateVerifyBody):
    context = _resolve_mfa_context(request, body.mfa_context_token)
    _assert_token_user_match(context, body.user_id)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT biometric_public_key, biometric_sign_count,
               biometric_challenge, username, role
        FROM users WHERE id=?
        """,
        (body.user_id,),
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found.")

    if not row["biometric_challenge"]:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail="No pending biometric authentication challenge. Call /biometric/authenticate-options first.",
        )

    expected_challenge = bytes(row["biometric_challenge"])
    public_key_bytes = bytes(row["biometric_public_key"])

    credentials = body.model_dump(exclude={"user_id", "mfa_context_token"})
    verification = verify_authentication(
        credentials,
        expected_challenge,
        public_key_bytes,
        row["biometric_sign_count"],
    )

    cursor.execute(
        "UPDATE users SET biometric_sign_count=?, biometric_challenge=NULL WHERE id=?",
        (verification.new_sign_count, body.user_id),
    )
    conn.commit()

    cursor.execute("SELECT username, role FROM users WHERE id=?", (body.user_id,))
    user_row = cursor.fetchone()
    conn.close()

    token = create_token(
        {
            "sub": body.user_id,
            "username": user_row["username"],
            "role": user_row["role"],
            "biometric": True,
            # Preserve original pending risk so subsequent step-up enforcement
            # remains consistent after strong MFA.
            "risk_score": float(context.get("risk_score", 0) or 0),
        }
    )

    return {"status": "verified", "access_token": token}


@router.post("/biometric/status")
def biometric_status(request: Request, body: StatusBody):
    context = _resolve_mfa_context(request, body.mfa_context_token)
    _assert_token_user_match(context, body.user_id)

    conn = get_db()
    cursor = conn.cursor()
    row = cursor.execute(
        "SELECT biometric_credential_id FROM users WHERE id=?",
        (body.user_id,),
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    registered = row["biometric_credential_id"] is not None
    return {"registered": bool(registered)}

