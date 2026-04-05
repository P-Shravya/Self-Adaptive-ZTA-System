# backend/database.py

import sqlite3
from pathlib import Path


# Get backend directory
BASE_DIR = Path(__file__).resolve().parent

# Define database path
DB_PATH = BASE_DIR / "dataset.db"


def get_db():
    """
    Creates connection to dataset.db.
    Enables row access as dictionary.
    """
    # Timeout + busy_timeout reduce transient lock errors under concurrency.
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000;")
    # Setting WAL can itself require a lock. Do it as best effort so opening a
    # connection never fails with 500 when DB is temporarily busy.
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
    except sqlite3.OperationalError:
        pass
    return conn


def create_tables():
    """
    Best-effort migrations for local SQLite.
    This keeps existing DBs working when we add new columns/tables.
    """
    conn = get_db()
    try:
        cur = conn.cursor()

        # Email OTP table (used for strong MFA email fallback)
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS email_otp_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                otp_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                attempt_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        # Add biometric columns to users table if missing.
        # SQLite has no IF NOT EXISTS for ADD COLUMN; we ignore "duplicate column" errors.
        user_cols = [
            ("biometric_credential_id", "BLOB"),
            ("biometric_public_key", "BLOB"),
            ("biometric_sign_count", "INTEGER"),
            ("biometric_challenge", "BLOB"),
        ]
        for col, col_type in user_cols:
            try:
                cur.execute(f"ALTER TABLE users ADD COLUMN {col} {col_type}")
            except sqlite3.OperationalError:
                pass

        # If the DB previously stored a platform-auth credential under older column names,
        # copy it forward once so existing enrollments continue working.
        try:
            cur.execute(
                """
                UPDATE users
                SET
                    biometric_credential_id = COALESCE(biometric_credential_id, webauthn_credential_id),
                    biometric_public_key    = COALESCE(biometric_public_key, webauthn_public_key),
                    biometric_sign_count    = COALESCE(biometric_sign_count, webauthn_sign_count),
                    biometric_challenge     = COALESCE(biometric_challenge, webauthn_challenge)
                """
            )
        except sqlite3.OperationalError:
            # Older DB might not have the legacy columns either.
            pass

        conn.commit()
    finally:
        conn.close()