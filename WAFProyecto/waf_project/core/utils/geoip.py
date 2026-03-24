import os
import time
import ipaddress
from typing import Optional, Dict, Any, Tuple


def resolve_mmdb_path(project_root: str) -> str:
    """
    Default location: <project_root>/GeoLite2-City.mmdb
    User must download from MaxMind and place it there.
    """
    return os.path.join(project_root, "GeoLite2-City.mmdb")


def load_geoip_reader(mmdb_path: str):
    """
    Returns a geoip2.database.Reader or None if not available.
    Kept defensive so the WAF runs even without the mmdb file.
    """
    if not os.path.exists(mmdb_path):
        print(f"[GeoIP] Missing database file: {mmdb_path}")
        print("[GeoIP] Download GeoLite2-City.mmdb from MaxMind and place it in the project root.")
        return None

    try:
        from geoip2.database import Reader  # imported lazily to avoid hard fail at import-time
        return Reader(mmdb_path)
    except Exception as e:
        print(f"[GeoIP] Failed to load database reader: {e}")
        return None


def geoip_lookup(reader, ip: str) -> Optional[Dict[str, Any]]:
    """
    Returns {lat, lon, country, city, source} when available, otherwise None.

    Behavior:
    - If IP is loopback/private: returns a synthetic "Local" location at (0, 0) so the Threat Map can still
      display markers during local development.
    - If MaxMind reader is available: uses it.
    - If reader is missing: tries a lightweight public fallback for public IPs (best-effort).
    """
    # Local/private IPs won't resolve in GeoIP DBs; still show something for demos.
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback or ip_obj.is_private:
            return {"lat": 0.0, "lon": 0.0, "country": "Local", "city": "Local", "source": "local"}
    except Exception:
        # Not a valid IP address
        return None

    if reader is None:
        return _fallback_geoip_http(ip)
    try:
        resp = reader.city(ip)
        lat = getattr(getattr(resp, "location", None), "latitude", None)
        lon = getattr(getattr(resp, "location", None), "longitude", None)
        if lat is None or lon is None:
            return _fallback_geoip_http(ip)
        country = getattr(getattr(resp, "country", None), "name", None)
        city = getattr(getattr(resp, "city", None), "name", None)
        return {"lat": float(lat), "lon": float(lon), "country": country, "city": city, "source": "maxmind"}
    except Exception:
        # Includes AddressNotFoundError and any parsing errors
        return _fallback_geoip_http(ip)


_FALLBACK_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def _fallback_geoip_http(ip: str) -> Optional[Dict[str, Any]]:
    """
    Best-effort fallback geolocation for public IPs when the mmdb is missing.
    Uses ip-api.com (no key) and caches results briefly to avoid rate limits.
    """
    now = time.time()
    cached = _FALLBACK_CACHE.get(ip)
    if cached and (now - cached[0]) < 3600:
        return cached[1]

    try:
        import requests
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,city,lat,lon"},
            timeout=2.5,
        )
        if r.status_code != 200:
            return None
        data = r.json()
        if data.get("status") != "success":
            return None
        lat = data.get("lat")
        lon = data.get("lon")
        if lat is None or lon is None:
            return None
        out = {
            "lat": float(lat),
            "lon": float(lon),
            "country": data.get("country"),
            "city": data.get("city"),
            "source": "ip-api",
        }
        _FALLBACK_CACHE[ip] = (now, out)
        return out
    except Exception:
        return None

