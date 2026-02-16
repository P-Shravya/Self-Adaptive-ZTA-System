from backend.database import get_db

def log_successful_login(metadata: dict):
    db = get_db()

    cursor = db.execute("""
        INSERT INTO behavior_logs (
            user_id,
            username,
            timestamp,
            hour,
            day_of_week,
            ip_address,
            ip_prefix,
            location_country,
            location_city,
            device_fingerprint,
            device_type,
            os,
            browser,
            resource,
            action,
            session_id,
            session_duration,
            vpn_detected,
            proxy_detected
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        metadata["user_id"],
        metadata["username"],
        metadata["timestamp"],
        metadata["hour"],
        metadata["day_of_week"],
        metadata["ip_address"],
        metadata["ip_prefix"],
        metadata["location_country"],
        metadata["location_city"],
        metadata["device_fingerprint"],
        metadata["device_type"],
        metadata["os"],
        metadata["browser"],
        metadata["resource"],
        metadata["action"],
        metadata["session_id"],
        metadata["session_duration"],
        metadata["vpn_detected"],
        metadata["proxy_detected"],
    ))

    db.commit()
    return cursor.lastrowid
