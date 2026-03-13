import os
from dotenv import load_dotenv   # ← add this

load_dotenv()                     # ← add this — reads .env before anything else

_secret = os.environ.get("ZTA_SECRET_KEY", "")

if not _secret:
    import warnings
    warnings.warn(
        "ZTA_SECRET_KEY environment variable is not set. "
        "Using an insecure fallback — DO NOT use this in production.",
        stacklevel=2
    )
    _secret = "CHANGE_THIS_SECRET_SET_ZTA_SECRET_KEY_ENV_VAR"

SECRET_KEY = _secret
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

LOW_RISK = 30
HIGH_RISK = 70