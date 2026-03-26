"""OSINT API clients for AbuseIPDB and VirusTotal.

Both APIs require user-provided keys configured via .env file.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import requests

from src.core.exceptions import IntelError

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


def abuseipdb_check(ip_address: str, timeout: int = 10) -> dict[str, Any]:
    """Check an IP against AbuseIPDB.

    Requires ABUSEIPDB_API_KEY environment variable.

    Args:
        ip_address: IP address to check.
        timeout: Request timeout in seconds.

    Returns:
        Dictionary with abuse confidence score and report count.
    """
    if not ip_address:
        raise ValueError("ip_address must not be empty")

    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        logger.debug("AbuseIPDB API key not configured")
        return {"ip_address": ip_address, "available": False}

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90",
    }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
    except requests.RequestException as exc:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip_address, exc)
        return {"ip_address": ip_address, "available": False, "error": str(exc)}

    return {
        "ip_address": ip_address,
        "available": True,
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "is_tor": data.get("isTor"),
        "last_reported_at": data.get("lastReportedAt"),
    }


def virustotal_check(ip_address: str, timeout: int = 10) -> dict[str, Any]:
    """Check an IP against VirusTotal.

    Requires VIRUSTOTAL_API_KEY environment variable.

    Args:
        ip_address: IP address to check.
        timeout: Request timeout in seconds.

    Returns:
        Dictionary with malicious detection counts.
    """
    if not ip_address:
        raise ValueError("ip_address must not be empty")

    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        logger.debug("VirusTotal API key not configured")
        return {"ip_address": ip_address, "available": False}

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    url = VIRUSTOTAL_URL.format(ip=ip_address)
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        data = response.json().get("data", {}).get("attributes", {})
    except requests.RequestException as exc:
        logger.warning("VirusTotal lookup failed for %s: %s", ip_address, exc)
        return {"ip_address": ip_address, "available": False, "error": str(exc)}

    analysis = data.get("last_analysis_stats", {})

    return {
        "ip_address": ip_address,
        "available": True,
        "malicious": analysis.get("malicious", 0),
        "suspicious": analysis.get("suspicious", 0),
        "harmless": analysis.get("harmless", 0),
        "undetected": analysis.get("undetected", 0),
        "country": data.get("country"),
        "as_owner": data.get("as_owner"),
        "reputation": data.get("reputation"),
    }
