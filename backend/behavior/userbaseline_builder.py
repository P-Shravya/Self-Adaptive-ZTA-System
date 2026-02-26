import json
from statistics import mean, stdev
from collections import Counter
from datetime import datetime
from backend.database import get_db


def build_user_baseline(user_id: int):

    db = get_db()

    rows = db.execute("""
        SELECT
            id,
            hour,
            day_of_week,
            ip_prefix,
            location_country,
            device_id,
            device_type,
            os,
            browser,
            session_duration,
            vpn_detected,
            failed_attempts,
            typing_avg,
            data_transfer,
            download_volume
        FROM behavior_logs
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 30
    """, (user_id,)).fetchall()

    if not rows:
        db.close()
        return None

    log_ids = []

    hours = []
    days = []
    ip_prefixes = []
    countries = []

    device_ids = []
    device_types = []
    os_list = []
    browsers = []

    durations = []
    vpn_flags = []
    failed_attempts_list = []

    typing_vals = []
    transfer_vals = []
    download_vals = []

    for r in rows:

        log_ids.append(r["id"])

        hours.append(r["hour"])
        days.append(r["day_of_week"])
        ip_prefixes.append(r["ip_prefix"])
        countries.append(r["location_country"])

        device_ids.append(r["device_id"])
        device_types.append(r["device_type"])
        os_list.append(r["os"])
        browsers.append(r["browser"])

        durations.append(r["session_duration"])
        vpn_flags.append(r["vpn_detected"])
        failed_attempts_list.append(r["failed_attempts"])

        typing_vals.append(r["typing_avg"])
        transfer_vals.append(r["data_transfer"])
        download_vals.append(r["download_volume"])

    baseline_data = {

        # ================= TEMPORAL =================
        "temporal": {
            "login_hours": {
                "mean": mean(hours),
                "std": stdev(hours) if len(hours) > 1 else 0,
                "min": min(hours),
                "max": max(hours),
                "distribution": dict(Counter(hours))
            },
            "day_of_week_distribution": dict(Counter(days))
        },

        # ================= NETWORK =================
        "network": {
            "ip_prefix_distribution": dict(Counter(ip_prefixes)),
            "country_distribution": dict(Counter(countries)),
            "vpn_usage_percentage": (sum(vpn_flags) / len(vpn_flags)) * 100
        },

        # ================= DEVICE =================
        "device": {
            "known_devices": list(set(device_ids)),
            "device_type_distribution": dict(Counter(device_types)),
            "os_distribution": dict(Counter(os_list)),
            "browser_distribution": dict(Counter(browsers))
        },

        # ================= SESSION =================
        "session": {
            "avg_duration": mean(durations) if durations else 0
        },

        # ================= BEHAVIOR =================
        "behavior": {
            "avg_typing": mean(typing_vals) if typing_vals else 0
        },

        # ================= DATA =================
        "data": {
            "avg_data_transfer": mean(transfer_vals) if transfer_vals else 1,
            "avg_download_volume": mean(download_vals) if download_vals else 1
        },

        # ================= SECURITY =================
        "security": {
            "avg_failed_attempts": mean(failed_attempts_list) if failed_attempts_list else 0
        }
    }

    # Store baseline in DB
    db.execute("""
        INSERT OR REPLACE INTO user_baselines
        (user_id, baseline_data, last_updated,
         data_points_count, source_log_ids)
        VALUES (?, ?, ?, ?, ?)
    """, (
        user_id,
        json.dumps(baseline_data),
        datetime.utcnow().isoformat(),
        len(rows),
        json.dumps(log_ids)
    ))

    db.commit()
    db.close()

    return baseline_data