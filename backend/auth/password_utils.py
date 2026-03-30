from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        # Treat malformed/legacy hash values as invalid credentials
        # instead of raising a 500.
        return False

def hash_password(password):
    return pwd_context.hash(password)