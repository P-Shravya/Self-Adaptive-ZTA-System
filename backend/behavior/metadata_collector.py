import uuid
import hashlib
import requests
from datetime import datetime
from ipaddress import ip_network
from geopy.distance import geodesic
from user_agents import parse
from backend.database import get_db


def extract_ip_prefix(ip):
    try:
        return str(ip_network(ip + "/24", strict=False))
    except:
        return None


def generate_device_id(user_agent, ip):
    return hashlib.sha256((user_agent + ip).encode()).hexdigest()


def collect_login_metadata(request, user_id, username):

    now = datetime.utcnow()
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "")

    # SAFE GEO LOOKUP
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=2
        )
        geo = response.json()
    except Exception:
        geo = {}

    country = geo.get("country")
    lat = geo.get("lat")
    lon = geo.get("lon")
    proxy = geo.get("proxy", False)

    db = get_db()

    last = db.execute("""
        SELECT timestamp, latitude, longitude
        FROM behavior_logs
        WHERE user_id=?
        ORDER BY timestamp DESC
        LIMIT 1
    """, (user_id,)).fetchone()

    geo_distance = 0
    time_diff = 999

    if last and lat and lon and last["latitude"] and last["longitude"]:
        last_time = datetime.fromisoformat(last["timestamp"])
        time_diff = (now - last_time).total_seconds() / 60

        try:
            geo_distance = geodesic(
                (lat, lon),
                (last["latitude"], last["longitude"])
            ).km
        except:
            geo_distance = 0

    ua = parse(user_agent)

    try:
        content_length = int(request.headers.get("content-length", 0))
    except:
        content_length = 0

    metadata = {
        "user_id": user_id,
        "username": username,
        "timestamp": now.isoformat(),
        "hour": now.hour,
        "login_hour": now.hour,
        "day_of_week": now.weekday(),

        "ip_address": ip,
        "ip_prefix": extract_ip_prefix(ip),
        "location_country": country,
        "latitude": lat,
        "longitude": lon,

        "geo_distance_km": geo_distance,
        "time_diff_minutes": time_diff,

        "device_id": generate_device_id(user_agent, ip),
        "device_type": ua.device.family,
        "os": ua.os.family,
        "browser": ua.browser.family,

        "resource": request.url.path,
        "action": "login_success",

        "session_id": str(uuid.uuid4()),
        "session_duration": 0,

        "vpn_detected": int(proxy),
        "proxy_detected": int(proxy),

        "failed_attempts": 0,

        "typing_avg": 0,
        "data_transfer": content_length,
        "download_volume": 0
    }

    db.close()
    return metadata
