# backend/webauthn/webauthn_utils.py

import json
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
)

RP_ID = "127.0.0.1"
RP_NAME = "ZTA-System"
ORIGIN = "http://127.0.0.1:8000"


def create_registration_options(user_id, username):
    """
    Returns (options_dict, challenge_bytes).
    Router MUST store challenge_bytes in DB for later verification.
    BUG 3 FIX: serialize with options_to_json() so FastAPI can return it.
    BUG 4 FIX: return challenge separately for server-side storage.
    """
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(user_id).encode(),
        user_name=username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
    )
    options_dict = json.loads(options_to_json(options))   # BUG 3 FIX
    return options_dict, options.challenge                  # BUG 4 FIX


def verify_registration(credentials, expected_challenge_bytes):
    """
    BUG 4 FIX: expected_challenge must be the original server-stored bytes,
    NOT the clientDataJSON from the client response.
    """
    return verify_registration_response(
        credential=credentials,
        expected_challenge=expected_challenge_bytes,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )


def create_authentication_options(credential_id_bytes):
    """
    BUG 3 FIX: serialize with options_to_json().
    BUG 4 FIX: return challenge for server-side storage.
    BUG 6 FIX: credential_id_bytes must be bytes (from DB BLOB), not string.
    """
    # Ensure bytes type
    if isinstance(credential_id_bytes, str):
        credential_id_bytes = credential_id_bytes.encode()

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[{
            "type": "public-key",
            "id": credential_id_bytes,              # BUG 6 FIX: bytes required
        }],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    options_dict = json.loads(options_to_json(options))   # BUG 3 FIX
    return options_dict, options.challenge                  # BUG 4 FIX


def verify_authentication(credentials, expected_challenge_bytes, public_key_bytes, sign_count):
    """
    BUG 4 FIX: use server-stored challenge bytes, not client data.
    """
    if isinstance(public_key_bytes, str):
        public_key_bytes = public_key_bytes.encode()

    return verify_authentication_response(
        credential=credentials,
        expected_challenge=expected_challenge_bytes,       # BUG 4 FIX
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        credential_public_key=public_key_bytes,
        credential_current_sign_count=sign_count,
    )