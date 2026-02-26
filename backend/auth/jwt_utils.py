# backend/auth/jwt_utils.py

from jose import jwt, JWTError, ExpiredSignatureError
from datetime import datetime, timedelta
from backend.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES


# ==========================================================
# 🔹 CREATE ACCESS TOKEN
# ==========================================================
def create_token(data: dict) -> str:
    """
    Creates JWT access token with:
        - issued at (iat)
        - expiration (exp)
    """

    payload = data.copy()

    now = datetime.utcnow()

    payload.update({
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
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