# backend/auth/jwt_utils.py

from jose import jwt, JWTError, ExpiredSignatureError
from datetime import datetime, timedelta, timezone
from backend.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES


# ==========================================================
# 🔹 CREATE ACCESS TOKEN
# ==========================================================
def create_token(data: dict, expiry_minutes: int = None) -> str:

    payload = data.copy()
    now = datetime.now(timezone.utc)

    # jose enforces JWT spec: "sub" should be a string
    if "sub" in payload and payload["sub"] is not None and not isinstance(payload["sub"], str):
        payload["sub"] = str(payload["sub"])

    # If custom expiry not provided → use default
    if expiry_minutes is None:
        expiry_minutes = ACCESS_TOKEN_EXPIRE_MINUTES

    # Use numeric timestamps for JWT standard claims
    iat = int(now.timestamp())
    exp = int((now + timedelta(minutes=expiry_minutes)).timestamp())

    payload.update({
        "iat": iat,
        "exp": exp
    })

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================================
# 🔹 VERIFY & DECODE TOKEN
# ==========================================================
def verify_token(token: str) -> dict | None:
    """
    Verifies token signature and expiration.

    Returns:
        payload dict if valid
        None if invalid or expired
    """

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload

    except ExpiredSignatureError:
        # Token expired
        return None

    except JWTError:
        # Invalid token
        return None