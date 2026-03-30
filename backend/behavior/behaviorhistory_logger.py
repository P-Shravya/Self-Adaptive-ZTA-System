from backend.database import get_db


def log_behavior_event(metadata: dict):
    """
    FIX: Renamed from log_successful_login() to log_behavior_event().
    The old name was misleading — this function logs ALL login events
    including failures (action='login_failed') and monitor activity.
    Renaming removes the false implication that only successes are logged.
    """
    db = get_db()
    try:
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
                latitude,
                longitude,
                geo_distance_km,
                time_diff_minutes,
                device_id,
                device_type,
                os,
                browser,
                resource,
                action,
                session_id,
                session_duration,
                vpn_detected,
                proxy_detected,
                failed_attempts,
                typing_avg,
                data_transfer,
                download_volume
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            metadata["user_id"],
            metadata["username"],
            metadata["timestamp"],
            metadata["hour"],
            metadata["day_of_week"],
            metadata["ip_address"],
            metadata["ip_prefix"],
            metadata["location_country"],
            metadata.get("latitude"),
            metadata.get("longitude"),
            metadata.get("geo_distance_km", 0),
            metadata.get("time_diff_minutes", 0),
            metadata.get("device_id"),
            metadata.get("device_type"),
            metadata.get("os"),
            metadata.get("browser"),
            metadata["resource"],
            metadata["action"],
            metadata.get("session_id"),
            metadata.get("session_duration", 0),
            metadata.get("vpn_detected", 0),
            metadata.get("proxy_detected", 0),
            metadata.get("failed_attempts", 0),
            metadata.get("typing_avg", 0),
            metadata.get("data_transfer", 0),
            metadata.get("download_volume", 0),
        ))
        db.commit()
        return cursor.lastrowid
    finally:
        db.close()


# Backward-compatibility alias so any callers not yet updated still work.
log_successful_login = log_behavior_event