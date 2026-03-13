# backend/mfa/mfa_utils.py

import pyotp
import random
import base64
import qrcode
from io import BytesIO


def generate_secret():
    return pyotp.random_base32()


def generate_qr(username, secret):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="ZTA-System")

    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")

    return base64.b64encode(buffer.getvalue()).decode()


def verify_totp(secret, otp):
    return pyotp.TOTP(secret).verify(otp)


def generate_email_otp():
    return str(random.randint(100000, 999999))
