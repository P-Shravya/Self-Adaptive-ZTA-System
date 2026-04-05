"""
Seed synthetic behavior history for deterministic step-up testing.

Creates 30 rows per selected user in `behavior_logs` where the last row is a
"current login" that scores into a target band when evaluated against the
previous 29 rows as the user's baseline.

Usage (from repo root):
  python -m backend.scripts.seed_behavior_logs
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from statistics import mean, stdev
from typing import Any, Iterable

from backend.database import get_db
from backend.behavior.userbaseline_builder import build_user_baseline
from backend.risk_engine.risk_engine import RiskEngine


@dataclass(frozen=True)
class TargetBand:
    label: str
    min_score: float
    max_score: float | None  # None means open-ended


TARGETS: dict[int, TargetBand] = {
    # 0–30 allow (casual/acceptable)
    9: TargetBand("allow", 0, 30),
    # 31–55 monitor
    1: TargetBand("monitor", 31, 55),
    2: TargetBand("monitor", 31, 55),
    # 56–70 mfa
    3: TargetBand("mfa", 56, 70),
    4: TargetBand("mfa", 56, 70),
    5: TargetBand("mfa", 56, 70),
    # 71–85 strong_mfa
    6: TargetBand("strong_mfa", 71, 85),
    7: TargetBand("strong_mfa", 71, 85),
    8: TargetBand("strong_mfa", 71, 85),
    # 86–95 manager approval (aligned with StepUpEngine / monitor middleware)
    10: TargetBand("manager_approval", 86, 95),
}

LOGIN_FAILED_ATTEMPTS_BY_USER: dict[int, int] = {
    1: 0,
    2: 0,
    3: 0,
    4: 0,
    5: 0,
    6: 1,  # keep strong_mfa stable after login without over-shooting into block
    7: 1,  # same fix
    8: 1,  # same fix
    9: 0,
    10: 0,  # manager path is driven by brute-force pattern + anomaly, not failed_attempts
}

BRUTE_FORCE_PATTERN_USERS = {3, 4, 5, 6, 7, 8, 10}

# User 10 (manager_approval): real /api/login Content-Length varies (~50–80 bytes).
# network_risk adds +30 only when current/avg_data_transfer > 2. Keep baseline avg
# low (~22) so smaller POSTs still clear ratio>2 after baseline drift from history.
USER_10_BASELINE_DATA_TRANSFER = 22


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _baseline_from_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    hours = [int(r["hour"]) for r in rows]
    session_durations = [int(r.get("session_duration") or 0) for r in rows]
    data_transfers = [int(r.get("data_transfer") or 0) for r in rows]
    download_volumes = [int(r.get("download_volume") or 0) for r in rows]
    device_ids = [r.get("device_id") for r in rows if r.get("device_id")]

    return {
        "avg_login_hour": mean(hours) if hours else 0,
        "login_hour_std": stdev(hours) if len(hours) > 1 else 0,
        "known_devices": list(sorted(set(device_ids))),
        "avg_session_duration": mean(session_durations) if session_durations else 1,
        "avg_data_transfer": mean(data_transfers) if data_transfers else 1,
        "avg_download_volume": mean(download_volumes) if download_volumes else 1,
    }


def _insert_behavior_row(db, row: dict[str, Any]) -> None:
    db.execute(
        """
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
            download_volume,
            location_city,
            device_fingerprint
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            row["user_id"],
            row["username"],
            row["timestamp"],
            row["hour"],
            row["day_of_week"],
            row.get("ip_address"),
            row.get("ip_prefix"),
            row.get("location_country"),
            row.get("latitude"),
            row.get("longitude"),
            row.get("geo_distance_km", 0),
            row.get("time_diff_minutes", 999),
            row.get("device_id"),
            row.get("device_type"),
            row.get("os"),
            row.get("browser"),
            row.get("resource"),
            row.get("action"),
            row.get("session_id"),
            row.get("session_duration", 0),
            row.get("vpn_detected", 0),
            row.get("proxy_detected", 0),
            row.get("failed_attempts", 0),
            row.get("typing_avg", 0),
            row.get("data_transfer", 0),
            row.get("download_volume", 0),
            row.get("location_city"),
            row.get("device_fingerprint"),
        ),
    )


def _make_baseline_rows(
    user_id: int,
    username: str,
    start: datetime,
    count: int,
    center_hour: int = 9,
) -> list[dict[str, Any]]:
    # Tight baseline around a center hour (std ≈ 1.0).
    # For strong_mfa users we center around current login hour so they remain in
    # strong_mfa after one real login instead of drifting to block.
    device_id = f"baseline-device-{user_id}"
    baseline_ip = f"203.0.113.{(user_id % 200) + 10}"
    baseline_prefix = "203.0.113.0/24"
    baseline_country = "US"
    baseline_city = "New York"
    lat, lon = 40.7128, -74.0060

    rows: list[dict[str, Any]] = []
    for i in range(count):
        ts = start + timedelta(hours=i * 8)
        hour = (center_hour + (i % 3) - 1) % 24
        rows.append(
            {
                "user_id": user_id,
                "username": username,
                "timestamp": _iso(ts),
                "hour": hour,
                "day_of_week": ts.weekday(),
                "ip_address": baseline_ip,
                "ip_prefix": baseline_prefix,
                "location_country": baseline_country,
                "location_city": baseline_city,
                "latitude": lat,
                "longitude": lon,
                "geo_distance_km": 0,
                "time_diff_minutes": 999,
                "device_id": device_id,
                "device_fingerprint": device_id,
                "device_type": "Laptop",
                "os": "Windows",
                "browser": "Chrome",
                "resource": "dashboard",
                "action": "login_success",
                "session_id": f"baseline-session-{user_id}-{i}",
                "session_duration": 10,
                "vpn_detected": 0,
                "proxy_detected": 0,
                "failed_attempts": 0,
                "typing_avg": 120.0,
                "data_transfer": 100,
                "download_volume": 10,
            }
        )
    return rows


def _make_risky_row(
    user_id: int,
    username: str,
    ts: datetime,
    band: TargetBand,
    center_hour: int | None = None,
) -> dict[str, Any]:
    # Always different device/network/location than baseline to simulate anomaly.
    risky_device = f"risky-device-{user_id}"
    baseline_device = f"baseline-device-{user_id}"

    # Different geo than baseline but avoid impossible_travel override by
    # forcing a large time_diff_minutes in the stored row.
    risky_ip = f"198.51.100.{(user_id % 200) + 20}"
    risky_prefix = "198.51.100.0/24"
    risky_country = "DE"
    risky_city = "Berlin"
    lat, lon = 52.5200, 13.4050

    # Tune risk by combining: new device (25), resource sensitivity (0–40),
    # login_time_anomaly (0–25), network ratio spike (0–30).
    if band.label == "monitor":
        resource = "patient_records"  # 0.6 * 40 = 24
        hour = 9  # keep close to baseline to avoid login_time_anomaly
        data_transfer = 100  # no spike (baseline ~100)
        session_duration = 20  # avoid +20 behavior_risk (4× baseline)
        device_id = risky_device
        device_fingerprint = risky_device
        ip_address = risky_ip
        ip_prefix = risky_prefix
        location_country = risky_country
        location_city = risky_city
        latitude = lat
        longitude = lon
        geo_distance_km = 800
        time_diff_minutes = 240
        os_name = "Linux"
        browser_name = "Firefox"
        vpn_detected = 1
        proxy_detected = 1
    elif band.label == "mfa":
        resource = "payroll"  # 0.9 * 40 = 36
        hour = 9
        data_transfer = 100
        session_duration = 20
        device_id = risky_device
        device_fingerprint = risky_device
        ip_address = risky_ip
        ip_prefix = risky_prefix
        location_country = risky_country
        location_city = risky_city
        latitude = lat
        longitude = lon
        geo_distance_km = 800
        time_diff_minutes = 240
        os_name = "Linux"
        browser_name = "Firefox"
        vpn_detected = 1
        proxy_detected = 1
    elif band.label == "strong_mfa":
        resource = "patient_records"  # 24 + device 25 + brute_force_pattern (+30) + failed_attempts (+10) ≈ 73
        # Match live login hour so cached baseline (login_success-only) stays aligned
        # and real /api/login does not pick up a bogus time anomaly.
        hour = center_hour if center_hour is not None else 9
        data_transfer = 100
        session_duration = 20
        device_id = risky_device
        device_fingerprint = risky_device
        ip_address = risky_ip
        ip_prefix = risky_prefix
        location_country = risky_country
        location_city = risky_city
        latitude = lat
        longitude = lon
        geo_distance_km = 800
        time_diff_minutes = 240
        os_name = "Linux"
        browser_name = "Firefox"
        vpn_detected = 1
        proxy_detected = 1
    elif band.label == "allow":
        # Casual/acceptable behavior that should remain low risk.
        resource = "dashboard"  # 0.2 * 40 = 8
        hour = 9
        data_transfer = 110
        session_duration = 12
        device_id = baseline_device
        device_fingerprint = baseline_device
        ip_address = f"203.0.113.{(user_id % 200) + 10}"
        ip_prefix = "203.0.113.0/24"
        location_country = "US"
        location_city = "New York"
        latitude = 40.7128
        longitude = -74.0060
        geo_distance_km = 0
        time_diff_minutes = 999
        os_name = "Windows"
        browser_name = "Chrome"
        vpn_detected = 0
        proxy_detected = 0
    else:
        # manager_approval: land in 86–95. With DB brute_force (+30), device (+25),
        # admin (+40) already sums to 95 — do not add a data_transfer spike or the
        # total clamps at 100 and fails the band check.
        resource = "admin"  # 40 + device 25 + brute 30 = 95 (when hour matches baseline)
        hour = center_hour if center_hour is not None else 9
        # Match USER_10_BASELINE_DATA_TRANSFER in seed main() so synthetic score
        # stays in 86–95 without an extra network spike on the risky row.
        data_transfer = USER_10_BASELINE_DATA_TRANSFER
        session_duration = 20  # remove behavior risk spike
        device_id = risky_device
        device_fingerprint = risky_device
        ip_address = risky_ip
        ip_prefix = risky_prefix
        location_country = risky_country
        location_city = risky_city
        latitude = lat
        longitude = lon
        geo_distance_km = 800
        time_diff_minutes = 240
        os_name = "Linux"
        browser_name = "Firefox"
        vpn_detected = 1
        proxy_detected = 1

    row_out = {
        "user_id": user_id,
        "username": username,
        "timestamp": _iso(ts),
        "hour": hour,
        "day_of_week": ts.weekday(),
        "ip_address": ip_address,
        "ip_prefix": ip_prefix,
        "location_country": location_country,
        "location_city": location_city,
        "latitude": latitude,
        "longitude": longitude,
        "geo_distance_km": geo_distance_km,
        "time_diff_minutes": time_diff_minutes,
        "device_id": device_id,
        "device_fingerprint": device_fingerprint,
        "device_type": "Laptop",
        "os": os_name,
        "browser": browser_name,
        "resource": resource,
        "action": "login_success",
        "session_id": f"risky-session-{user_id}",
        "session_duration": session_duration,
        "vpn_detected": vpn_detected,
        "proxy_detected": proxy_detected,
        "failed_attempts": 0,
        "typing_avg": 80.0,
        "data_transfer": data_transfer,
        "download_volume": 10,
    }

    # Real login compares current IP geo to the *latest* behavior_logs row.
    # If that row used a far-away synthetic lat/lon, a login within 30 minutes
    # triggers impossible_travel (score 100) and everything becomes "block".
    # Drop coordinates on synthetic risky rows so collect_login_metadata skips
    # travel math and uses safe defaults (geo_distance=0, time_diff=999).
    if band.label != "allow":
        row_out["latitude"] = None
        row_out["longitude"] = None
        row_out["geo_distance_km"] = 0
        row_out["time_diff_minutes"] = 999

    return row_out


def _risk_score_for(meta_row: dict[str, Any], baseline_rows: list[dict[str, Any]]) -> float:
    baseline = _baseline_from_rows(baseline_rows)
    meta = {
        "user_id": meta_row["user_id"],
        "device_id": meta_row.get("device_id"),
        "resource": meta_row.get("resource"),
        "failed_attempts": meta_row.get("failed_attempts", 0),
        "geo_distance_km": meta_row.get("geo_distance_km", 0),
        "time_diff_minutes": meta_row.get("time_diff_minutes", 999),
        "login_hour": meta_row.get("hour"),
        "session_duration": meta_row.get("session_duration", 0),
        "data_transfer": meta_row.get("data_transfer", 0),
        "download_volume": meta_row.get("download_volume", 0),
    }
    engine = RiskEngine()
    return float(engine.evaluate(meta, baseline)["score"])


def _ensure_users_exist(db, user_ids: Iterable[int]) -> dict[int, str]:
    user_ids = list(user_ids)
    rows = db.execute(
        f"SELECT id, username FROM users WHERE id IN ({','.join(['?'] * len(user_ids))})",
        tuple(user_ids),
    ).fetchall()
    return {int(r["id"]): str(r["username"]) for r in rows}


def _apply_bruteforce_history(rows: list[dict[str, Any]], user_id: int) -> None:
    """
    Make the latest 4 historical events all failures.
    On next real login, identity_risk recent-5 check (which includes the new
    login_success) still keeps 3 failures and adds brute_force_pattern.
    """
    if user_id not in BRUTE_FORCE_PATTERN_USERS or len(rows) < 4:
        return
    rows[-4]["action"] = "login_failed"
    rows[-3]["action"] = "login_failed"
    rows[-2]["action"] = "login_failed"
    rows[-1]["action"] = "login_failed"
    rows[-4]["failed_attempts"] = 1
    rows[-3]["failed_attempts"] = 2
    rows[-2]["failed_attempts"] = 3
    rows[-1]["failed_attempts"] = 4


def main() -> None:
    db = get_db()
    try:
        user_ids = sorted(TARGETS.keys())
        usernames = _ensure_users_exist(db, user_ids)
        missing = [uid for uid in user_ids if uid not in usernames]
        if missing:
            raise SystemExit(f"Missing users in `users` table: {missing}")

        # Demo flow: user 9 opens manager.html; user 10 is on manager-approval login path.
        db.execute("UPDATE users SET role=? WHERE id=?", ("manager", 9))
        db.execute("UPDATE users SET role=? WHERE id=?", ("employee", 10))
        db.commit()

        try:
            db.execute("DELETE FROM approval_requests")
            db.execute("DELETE FROM approval_logs")
            db.commit()
        except sqlite3.OperationalError:
            db.rollback()

        # Full reset: replace all behavior logs with synthetic deterministic data.
        db.execute("DELETE FROM behavior_logs")
        # Baselines must be rebuilt from the new logs.
        db.execute("DELETE FROM user_baselines")
        db.commit()

        now_utc = datetime.now(timezone.utc)
        live_login_hour = now_utc.hour
        start = now_utc - timedelta(days=30)

        for uid in user_ids:
            username = usernames[uid]
            band = TARGETS[uid]

            center_hour = live_login_hour if uid in {6, 7, 8, 10} else 9
            baseline_rows = _make_baseline_rows(uid, username, start, count=29, center_hour=center_hour)
            # Low avg data_transfer so typical login POST (~62 bytes) => ratio > 2 (+30 network).
            if uid == 10:
                for r in baseline_rows:
                    r["data_transfer"] = USER_10_BASELINE_DATA_TRANSFER
            _apply_bruteforce_history(baseline_rows, uid)
            risky_ts = start + timedelta(days=29, hours=23)
            ch = live_login_hour if uid in {6, 7, 8, 10} else None
            risky_row = _make_risky_row(uid, username, risky_ts, band, center_hour=ch)

            # RiskEngine identity_risk loads recent failures from the DB. For MFA/monitor
            # users, validating *after* inserting baseline would wrongly add
            # brute_force_pattern (+30) to the synthetic risky-row score. Strong MFA and
            # manager users need that DB signal, so insert their baselines first.
            brute_dependent = uid in {6, 7, 8, 10}
            if brute_dependent:
                for r in baseline_rows:
                    _insert_behavior_row(db, r)
                db.commit()

            score = _risk_score_for(risky_row, baseline_rows)
            if band.max_score is None:
                ok = score > band.min_score
            else:
                ok = band.min_score <= score <= band.max_score

            if not ok:
                raise SystemExit(
                    f"user_id={uid} target={band.label} expected {band.min_score}..{band.max_score} got {score}"
                )

            if not brute_dependent:
                for r in baseline_rows:
                    _insert_behavior_row(db, r)
                db.commit()

            _insert_behavior_row(db, risky_row)
            db.commit()

            print(f"user_id={uid} inserted=30 target={band.label} risky_score={score}")

            # Control login-time risk for next real /api/login evaluation.
            db.execute(
                "UPDATE users SET failed_attempts=? WHERE id=?",
                (LOGIN_FAILED_ATTEMPTS_BY_USER.get(uid, 0), uid),
            )
            db.commit()

        # Rebuild baselines from freshly-seeded logs.
        rebuilt = 0
        for uid in user_ids:
            baseline = build_user_baseline(uid)
            if baseline:
                rebuilt += 1
        print(f"user_baselines rebuilt={rebuilt}")

        # Sanity-check expected next-login bands using real DB-backed evaluation
        # (includes identity_risk recent behavior lookup).
        engine = RiskEngine()
        for uid in user_ids:
            row = db.execute(
                "SELECT baseline_data FROM user_baselines WHERE user_id=?",
                (uid,),
            ).fetchone()
            baseline_raw = json.loads(row["baseline_data"]) if row else {}
            baseline = {
                "avg_login_hour": baseline_raw["temporal"]["login_hours"]["mean"],
                "login_hour_std": baseline_raw["temporal"]["login_hours"]["std"],
                "known_devices": baseline_raw["device"]["known_devices"],
                "avg_session_duration": baseline_raw["session"]["avg_duration"],
                "avg_data_transfer": baseline_raw["data"]["avg_data_transfer"],
                "avg_download_volume": baseline_raw["data"]["avg_download_volume"],
            }
            # Use a likely new device except user 9 (allow profile).
            device_id = "baseline-device-9" if uid == 9 else f"live-device-{uid}"
            # Simulate immediate next login conditions:
            # - strong_mfa users (6/7/8) login around current hour
            # - manager user (10) also uses current hour, against fixed baseline
            #   to keep score in manager-approval range (about high-80s)
            login_hour = live_login_hour if uid in {6, 7, 8, 10} else 9
            # Match observed real login Content-Length (~62) for user 10.
            sim_transfer = 62 if uid == 10 else 0
            meta = {
                "user_id": uid,
                "device_id": device_id,
                "resource": "/api/login",
                "failed_attempts": LOGIN_FAILED_ATTEMPTS_BY_USER.get(uid, 0),
                "geo_distance_km": 0,
                "time_diff_minutes": 999,
                "login_hour": login_hour,
                "session_duration": 0,
                "data_transfer": sim_transfer,
                "download_volume": 0,
            }
            score = float(engine.evaluate(meta, baseline)["score"])
            band = TARGETS[uid]
            if band.max_score is None:
                ok = score > band.min_score
            else:
                ok = band.min_score <= score <= band.max_score
            print(f"next_login_check user_id={uid} score={score} target={band.label} ok={ok}")

    finally:
        db.close()


if __name__ == "__main__":
    main()