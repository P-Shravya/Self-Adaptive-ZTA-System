import os
import smtplib
import ssl
from email.message import EmailMessage
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()


def _get_env(name: str, default: str | None = None) -> str | None:
    val = os.getenv(name)
    return val if val is not None else default


def send_email_otp(to_email: str, otp: str) -> dict:
    """
    Sends an OTP to the user via SMTP.

    If SMTP is not configured and EMAIL_OTP_DEBUG=true, returns a debug payload
    so you can test the flow locally.
    """
    smtp_host = _get_env("SMTP_HOST")
    smtp_port = _get_env("SMTP_PORT", "587")
    smtp_username = _get_env("SMTP_USERNAME")
    smtp_password = _get_env("SMTP_PASSWORD")
    smtp_from = _get_env("SMTP_FROM_EMAIL", smtp_username)

    debug_enabled = (_get_env("EMAIL_OTP_DEBUG", "false") or "").lower() in ("1", "true", "yes")

    if not smtp_host or not smtp_username or not smtp_password or not smtp_from:
        if debug_enabled:
            # For dev/testing: do not error, allow frontend to verify using the returned OTP.
            print(f"[EMAIL_OTP_DEBUG] OTP for {to_email}: {otp} (at {datetime.utcnow().isoformat()}Z)")
            return {"sent": False, "debug_otp": otp}

        raise RuntimeError("SMTP not configured. Set SMTP_HOST/SMTP_USERNAME/SMTP_PASSWORD (and optionally EMAIL_OTP_DEBUG=true).")

    subject = _get_env("EMAIL_OTP_SUBJECT", "Your ZTA OTP Code") or "Your ZTA OTP Code"
    body = f"Your one-time verification code is: {otp}\n\nThis code expires in a few minutes."

    msg = EmailMessage()
    msg["From"] = smtp_from
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    port_int = int(smtp_port)
    use_ssl = port_int == 465

    context = ssl.create_default_context()

    if use_ssl:
        with smtplib.SMTP_SSL(smtp_host, port_int, context=context) as server:
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(smtp_host, port_int) as server:
            server.starttls(context=context)
            server.login(smtp_username, smtp_password)
            server.send_message(msg)

    return {"sent": True}

