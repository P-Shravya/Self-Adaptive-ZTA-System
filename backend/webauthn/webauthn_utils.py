# backend/webauthn/webauthn_utils.py

import os
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response
)

RP_ID = "localhost"
RP_NAME = "ZTA-System"
ORIGIN = "http://localhost:8000"


def create_registration_options(user_id, username):

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(user_id).encode(),
        user_name=username,
    )

    return options


def verify_registration(credentials, expected_challenge):

    verification = verify_registration_response(
        credential=credentials,
        expected_challenge=expected_challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
    )

    return verification


def create_authentication_options(credential_id):

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[{
            "type": "public-key",
            "id": credential_id
        }]
    )

    return options


def verify_authentication(credentials, expected_challenge, public_key, sign_count):

    verification = verify_authentication_response(
        credential=credentials,
        expected_challenge=expected_challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        credential_public_key=public_key,
        credential_current_sign_count=sign_count
    )

    return verification