"""GeoIP lookup for IP address geolocation.

Uses free online APIs with caching.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import requests

from src.core.exceptions import IntelError

logger = logging.getLogger(__name__)

GEOIP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp,org,as"
GEOIP_TIMEOUT_SECONDS = 10
RATE_LIMIT_DELAY = 1.5  # ip-api.com allows 45 req/min


_last_request_time: float = 0.0


def geoip_lookup(ip_address: str, timeout: int = GEOIP_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Look up geographic location of an IP address.

    Uses ip-api.com free API (no key required, rate limited).

    Args:
        ip_address: IP address to look up.
        timeout: Request timeout in seconds.

    Returns:
        Dictionary with country, city, lat, lon, ISP, org.

    Raises:
        ValueError: If ip_address is empty.
    """
    if not ip_address:
        raise ValueError("ip_address must not be empty")

    global _last_request_time
    elapsed = time.monotonic() - _last_request_time
    if elapsed < RATE_LIMIT_DELAY:
        time.sleep(RATE_LIMIT_DELAY - elapsed)

    url = GEOIP_API_URL.format(ip=ip_address)
    try:
        response = requests.get(url, timeout=timeout)
        _last_request_time = time.monotonic()
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        logger.warning("GeoIP lookup failed for %s: %s", ip_address, exc)
        return _empty_result(ip_address)

    if data.get("status") != "success":
        logger.debug("GeoIP lookup returned non-success for %s", ip_address)
        return _empty_result(ip_address)

    result = {
        "ip_address": ip_address,
        "country": data.get("country"),
        "city": data.get("city"),
        "latitude": data.get("lat"),
        "longitude": data.get("lon"),
        "isp": data.get("isp"),
        "organization": data.get("org"),
        "as_number": data.get("as"),
    }

    logger.debug("GeoIP for %s: %s, %s", ip_address, result["country"], result["city"])
    return result


def _empty_result(ip_address: str) -> dict[str, Any]:
    """Return an empty GeoIP result.

    Args:
        ip_address: The queried IP.

    Returns:
        Empty result dictionary.
    """
    return {
        "ip_address": ip_address,
        "country": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "isp": None,
        "organization": None,
        "as_number": None,
    }
