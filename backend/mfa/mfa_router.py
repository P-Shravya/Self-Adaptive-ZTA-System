# backend/mfa/mfa_router.py

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from datetime import datetime, timedelta
import random

from backend.database import get_db
from backend.auth.jwt_utils import create_token, verify_token
from backend.mfa.mfa_utils import generate_secret, generate_qr, verify_totp
from backend.auth.password_utils import hash_password, verify_password
from backend.notifications.email_utils import send_email_otp

router = APIRouter()

class SetupBody(BaseModel):
    user_id: int | None = None
    # Fallback when Authorization header is dropped by client/proxy (still HTTPS-only in prod).
    mfa_context_token: str | None = None

class VerifyBody(BaseModel):
    user_id: int | None = None
    otp: str
    risk_score: float = 0.0
    mfa_context_token: str | None = None


class EmailOtpRequestBody(BaseModel):
    mfa_context_token: str | None = None


class EmailOtpVerifyBody(BaseModel):
    otp: str
    mfa_context_token: str | None = None


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
    """
    Collect raw JWT strings. Body first — some browsers/proxies drop Authorization
    on POST while JSON body still arrives intact.
    """
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
    last_err = "Missing MFA token."
    for jwt_str in _jwt_candidates(request, body_token):
        payload = verify_token(jwt_str)
        if not payload:
            last_err = "Invalid or expired MFA token."
            continue
        if payload.get("sub") is None:
            last_err = "Invalid MFA token context."
            continue
        return payload
    raise HTTPException(status_code=401, detail=last_err)


@router.post("/mfa/setup")
def setup_mfa(request: Request, body: SetupBody):
    context = _resolve_mfa_context(request, body.mfa_context_token)
    try:
        token_user_id = int(context.get("sub"))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid MFA token.")
    # Use JWT `sub` as the source of truth.
    # We intentionally ignore `body.user_id` to avoid frontend caching / stale payload causing false 403s.
    user_id = token_user_id

    conn = get_db()
    cursor = conn.cursor()

    # Load user and enrollment state
    cursor.execute(
        "SELECT username, mfa_secret, mfa_enabled FROM users WHERE id=?",
        (user_id,)
    )
    row = cursor.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent re-enrollment once setup is completed.
    if int(row["mfa_enabled"] or 0) == 1:
        conn.close()
        raise HTTPException(
            status_code=409,
            detail="MFA is already configured for this user."
        )

    # If secret already exists but MFA isn't finalized yet, reuse the same
    # secret so the user can complete enrollment. Once mfa_enabled=1, we block
    # any further QR issuance (see above).
    if row["mfa_secret"]:
        secret = row["mfa_secret"]
    else:
        # First-time setup: generate a dedicated secret for this user.
        secret = generate_secret()
        cursor.execute(
            "UPDATE users SET mfa_secret=?, mfa_enabled=0 WHERE id=?",
            (secret, user_id)
        )
        conn.commit()

    conn.close()

    # Bind QR identity to username (not a shared/static value).
    try:
        qr = generate_qr(row["username"], secret)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"QR generation failed (check Pillow/qrcode install): {e!s}"
        ) from e

    return {"qr_code_base64": qr}

@router.post("/mfa/verify")
def verify_mfa(request: Request, body: VerifyBody):
    context = _resolve_mfa_context(request, body.mfa_context_token)
    try:
        token_user_id = int(context.get("sub"))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid MFA token.")
    # Use JWT `sub` as the source of truth.
    user_id = token_user_id

    otp = body.otp

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT username, role, mfa_secret, mfa_enabled FROM users WHERE id=?", (user_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    if not row["mfa_secret"]:
        conn.close()
        raise HTTPException(status_code=400, detail="MFA is not configured. Please set up MFA first.")

    if not verify_totp(row["mfa_secret"], otp):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid OTP")

    # Mark enrollment complete on first successful verification.
    if int(row["mfa_enabled"] or 0) == 0:
        cursor.execute("UPDATE users SET mfa_enabled=1 WHERE id=?", (user_id,))
        conn.commit()

    conn.close()

    # FIX: preserve risk_score in the post-MFA token.
    # Previously create_token() was called without risk_score, so the new JWT
    # had risk_score=None, making the user appear risk-free after MFA and
    # bypassing all subsequent step-up checks in require_role_access().
    token = create_token({
        "sub": user_id,
        "username": row["username"],
        "role": row["role"],
        "mfa": True,
        "risk_score": float(context.get("risk_score", body.risk_score))
    })

    return {"access_token": token}


# ============================================================
# Email OTP for strong_mfa (biometric fallback)
# ============================================================

@router.post("/mfa/email/request")
def request_email_otp(request: Request, body: EmailOtpRequestBody):
    context = _resolve_mfa_context(request, body.mfa_context_token)
    try:
        user_id = int(context.get("sub"))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid MFA token.")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT email, username, role FROM users WHERE id=?",
        (user_id,)
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    if not row["email"]:
        conn.close()
        raise HTTPException(status_code=400, detail="User has no email configured.")

    otp = str(random.randint(100000, 999999))
    otp_hash = hash_password(otp)

    now = datetime.utcnow()
    expires_at = (now + timedelta(minutes=5)).isoformat()
    created_at = now.isoformat()

    # Invalidate previous unused challenges.
    cursor.execute(
        "UPDATE email_otp_challenges SET consumed=1 WHERE user_id=? AND consumed=0",
        (user_id,)
    )

    cursor.execute(
        """
        INSERT INTO email_otp_challenges (
            user_id, otp_hash, expires_at, created_at, consumed, attempt_count
        ) VALUES (?, ?, ?, ?, 0, 0)
        """,
        (user_id, otp_hash, expires_at, created_at)
    )
    conn.commit()
    conn.close()

    try:
        send_result = send_email_otp(row["email"], otp)
    except Exception as e:
        # Don't leak OTP in response; only expose in debug mode inside send_email_otp.
        raise HTTPException(status_code=500, detail=str(e)) from e

    resp = {
        "status": "sent",
        "expires_in_seconds": 300
    }
    if send_result.get("debug_otp"):
        resp["debug_otp"] = send_result["debug_otp"]
    return resp


@router.post("/mfa/email/verify")
def verify_email_otp(request: Request, body: EmailOtpVerifyBody):
    context = _resolve_mfa_context(request, body.mfa_context_token)
    try:
        user_id = int(context.get("sub"))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid MFA token.")

    otp = (body.otp or "").strip()
    if not otp.isdigit() or len(otp) != 6:
        raise HTTPException(status_code=400, detail="OTP must be a 6-digit number.")

    conn = get_db()
    cursor = conn.cursor()

    now = datetime.utcnow().isoformat()
    cursor.execute(
        """
        SELECT id, otp_hash
        FROM email_otp_challenges
        WHERE user_id=? AND consumed=0 AND expires_at>?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (user_id, now)
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=400, detail="Email OTP expired or not requested.")

    if not verify_password(otp, row["otp_hash"]):
        cursor.execute(
            "UPDATE email_otp_challenges SET attempt_count=attempt_count+1 WHERE id=?",
            (row["id"],)
        )
        conn.commit()
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid OTP")

    cursor.execute(
        "UPDATE email_otp_challenges SET consumed=1 WHERE id=?",
        (row["id"],)
    )

    cursor.execute(
        "SELECT username, role FROM users WHERE id=?",
        (user_id,)
    )
    user_row = cursor.fetchone()

    conn.commit()
    conn.close()

    if not user_row:
        raise HTTPException(status_code=404, detail="User not found")

    token = create_token({
        "sub": user_id,
        "username": user_row["username"],
        "role": user_row["role"],
        "mfa": True,
        "email_mfa": True,
        "risk_score": float(context.get("risk_score", 0) or 0)
    })

    return {"access_token": token}