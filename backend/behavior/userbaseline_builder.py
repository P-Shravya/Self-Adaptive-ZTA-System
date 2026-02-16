import json
from statistics import mean, stdev
from collections import Counter
from datetime import datetime
from backend.database import get_db


def build_user_baseline(user_id: int):
    db = get_db()

    rows = db.execute("""
        SELECT id, hour, day_of_week, ip_prefix,
               location_country, location_city,
               device_fingerprint, device_type,
               os, browser,
               resource, session_duration,
               vpn_detected, proxy_detected
        FROM behavior_logs
        WHERE user_id = ?
        ORDER BY timestamp DESC
        LIMIT 30
    """, (user_id,)).fetchall()

    if not rows:
        return None

    log_ids = []
    hours = []
    days = []
    ip_prefixes = []
    countries = []
    cities = []
    fingerprints = []
    device_types = []
    os_list = []
    browsers = []
    resources = []
    durations = []
    vpn_flags = []
    proxy_flags = []

    for r in rows:
        log_ids.append(r[0])
        hours.append(r[1])
        days.append(r[2])
        ip_prefixes.append(r[3])
        countries.append(r[4])
        cities.append(r[5])
        fingerprints.append(r[6])
        device_types.append(r[7])
        os_list.append(r[8])
        browsers.append(r[9])
        resources.append(r[10])
        durations.append(r[11])
        vpn_flags.append(r[12])
        proxy_flags.append(r[13])

    baseline_data = {
        "temporal": {
            "login_hours": {
                "mean": mean(hours),
                "std": stdev(hours) if len(hours) > 1 else 0,
                "min": min(hours),
                "max": max(hours),
                "distribution": dict(Counter(hours))
            },
            "day_of_week": dict(Counter(days))
        },
        "network": {
            "ip_prefixes": dict(Counter(ip_prefixes)),
            "countries": dict(Counter(countries)),
            "cities": dict(Counter(cities)),
            "vpn_usage_percentage": (sum(vpn_flags) / len(vpn_flags)) * 100,
            "proxy_usage_percentage": (sum(proxy_flags) / len(proxy_flags)) * 100
        },
        "device": {
            "device_fingerprints": list(set(fingerprints)),
            "device_types": dict(Counter(device_types)),
            "os_distribution": dict(Counter(os_list)),
            "browser_distribution": dict(Counter(browsers))
        },
        "resource_access": {
            "resources": dict(Counter(resources))
        },
        "session": {
            "duration": {
                "mean": mean(durations),
                "std": stdev(durations) if len(durations) > 1 else 0,
                "min": min(durations),
                "max": max(durations)
            }
        },
        "security_flags": {
            "vpn_detected_count": sum(vpn_flags),
            "proxy_detected_count": sum(proxy_flags)
        }
    }

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

    return baseline_data
