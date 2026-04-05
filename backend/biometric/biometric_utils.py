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

# Windows Hello fingerprint uses the platform authenticator under the WebAuthn API.
# We expose it as "biometric fingerprint" in our app.
RP_ID = "127.0.0.1"
RP_NAME = "ZTA-System"
ORIGIN = "http://127.0.0.1:8000"


def create_registration_options(user_id, username):
    """
    Returns (options_dict, challenge_bytes).
    Router stores challenge_bytes in DB for later verification.
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
    options_dict = json.loads(options_to_json(options))
    return options_dict, options.challenge


def verify_registration(credentials, expected_challenge_bytes):
    return verify_registration_response(
        credential=credentials,
        expected_challenge=expected_challenge_bytes,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )


def create_authentication_options(credential_id_bytes):
    if isinstance(credential_id_bytes, str):
        credential_id_bytes = credential_id_bytes.encode()

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            {
                "type": "public-key",
                "id": credential_id_bytes,
            }
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    options_dict = json.loads(options_to_json(options))
    return options_dict, options.challenge


def verify_authentication(credentials, expected_challenge_bytes, public_key_bytes, sign_count):
    if isinstance(public_key_bytes, str):
        public_key_bytes = public_key_bytes.encode()

    return verify_authentication_response(
        credential=credentials,
        expected_challenge=expected_challenge_bytes,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        credential_public_key=public_key_bytes,
        credential_current_sign_count=sign_count,
    )

