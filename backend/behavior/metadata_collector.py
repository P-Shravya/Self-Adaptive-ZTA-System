import uuid
import hashlib
import httpx                          # FIX: replaced requests with httpx for async support
import asyncio
from datetime import datetime
from ipaddress import ip_network
from geopy.distance import geodesic
from user_agents import parse
from backend.database import get_db

# FIX: Simple in-process geo cache so repeated lookups for the same IP
# (especially in monitor middleware) don't fire a new HTTP call every time.
# Cache entries expire after GEO_CACHE_TTL_SECONDS seconds.
import time
_geo_cache: dict = {}
GEO_CACHE_TTL_SECONDS = 300   # 5 minutes


def extract_ip_prefix(ip):
    try:
        return str(ip_network(ip + "/24", strict=False))
    except Exception:
        return None


def generate_device_id(user_agent, ip):
    return hashlib.sha256((user_agent + ip).encode()).hexdigest()


async def _fetch_geo(ip: str) -> dict:
    """
    FIX: Async geo lookup with in-memory cache.
    - Uses httpx.AsyncClient so it never blocks the event loop.
    - Results are cached per IP for GEO_CACHE_TTL_SECONDS to avoid hammering
      ip-api.com on every monitored request (the main perf hotspot).
    """
    now = time.monotonic()
    cached = _geo_cache.get(ip)
    if cached and (now - cached["ts"]) < GEO_CACHE_TTL_SECONDS:
        return cached["data"]

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(f"http://ip-api.com/json/{ip}")
            geo = response.json()
    except Exception:
        geo = {}

    _geo_cache[ip] = {"data": geo, "ts": now}
    return geo


async def collect_login_metadata(request, user_id, username):
    """
    FIX: Now an async function so it can await the geo lookup without
    blocking the event loop (previously used synchronous requests.get()).
    Callers in auth_router and monitor_middleware must await this.
    """

    now = datetime.utcnow()
    ip = request.client.host
    user_agent = request.headers.get("user-agent", "")

    # FIX: Async + cached geo lookup
    geo = await _fetch_geo(ip)

    country = geo.get("country")
    city = geo.get("city")
    lat = geo.get("lat")
    lon = geo.get("lon")
    proxy = geo.get("proxy", False)

    db = get_db()
    try:
        # FIX: wrapped in try/finally so the connection is always closed even
        # if an exception occurs during geo lookup or UA parse.
        last = db.execute("""
            SELECT timestamp, latitude, longitude
            FROM behavior_logs
            WHERE user_id=?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (user_id,)).fetchone()
    finally:
        db.close()

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
        except Exception:
            geo_distance = 0

    ua = parse(user_agent)

    try:
        content_length = int(request.headers.get("content-length", 0))
    except Exception:
        content_length = 0

    # FIX: compute device_id once, removed the duplicate "device_fingerprint"
    # key that was computed a second time and never actually read anywhere.
    device_id = generate_device_id(user_agent, ip)

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
        "location_city": city,
        "latitude": lat,
        "longitude": lon,

        "geo_distance_km": geo_distance,
        "time_diff_minutes": time_diff,

        "device_id": device_id,          # FIX: single key, computed once
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

    return metadata