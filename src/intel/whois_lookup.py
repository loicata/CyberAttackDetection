"""WHOIS lookup for IP address ownership information."""

from __future__ import annotations

import logging
import subprocess
from src.core.subprocess_utils import run_silent
from typing import Any

from src.core.exceptions import IntelError

logger = logging.getLogger(__name__)

WHOIS_TIMEOUT_SECONDS = 15


def whois_lookup(ip_address: str) -> dict[str, Any]:
    """Perform WHOIS lookup on an IP address.

    Uses the system whois command or nslookup as fallback.

    Args:
        ip_address: IP address to look up.

    Returns:
        Dictionary with organization, country, and raw WHOIS data.

    Raises:
        ValueError: If ip_address is empty.
    """
    if not ip_address:
        raise ValueError("ip_address must not be empty")

    # Try whois command first
    result = _try_whois_command(ip_address)
    if result:
        return result

    # Fallback: try nslookup for basic info
    return _try_nslookup_fallback(ip_address)


def _try_whois_command(ip_address: str) -> dict[str, Any] | None:
    """Try using the whois command-line tool.

    Args:
        ip_address: IP to query.

    Returns:
        Parsed WHOIS data or None if command not available.
    """
    try:
        result = run_silent(["whois", ip_address], timeout=WHOIS_TIMEOUT_SECONDS)
        if result.returncode == 0 and result.stdout:
            return _parse_whois_output(result.stdout, ip_address)
    except FileNotFoundError:
        logger.debug("whois command not available")
    except subprocess.TimeoutExpired:
        logger.warning("WHOIS lookup timed out for %s", ip_address)

    return None


def _parse_whois_output(output: str, ip_address: str) -> dict[str, Any]:
    """Parse raw WHOIS output for key fields.

    Args:
        output: Raw WHOIS text.
        ip_address: The queried IP.

    Returns:
        Parsed WHOIS data dictionary.
    """
    org = None
    country = None

    for line in output.splitlines():
        line_lower = line.lower().strip()
        if line_lower.startswith("orgname:") or line_lower.startswith("org-name:"):
            org = line.split(":", 1)[1].strip()
        elif line_lower.startswith("country:"):
            country = line.split(":", 1)[1].strip()
        elif line_lower.startswith("organization:"):
            org = org or line.split(":", 1)[1].strip()

    return {
        "ip_address": ip_address,
        "organization": org,
        "country": country,
        "raw": output[:2000],  # Limit raw output size
    }


def _try_nslookup_fallback(ip_address: str) -> dict[str, Any]:
    """Fallback using nslookup for basic reverse lookup.

    Args:
        ip_address: IP to query.

    Returns:
        Basic WHOIS-like data from nslookup.
    """
    try:
        result = run_silent(["nslookup", ip_address], timeout=10)
        return {
            "ip_address": ip_address,
            "organization": None,
            "country": None,
            "raw": result.stdout[:1000] if result.stdout else "",
        }
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {
            "ip_address": ip_address,
            "organization": None,
            "country": None,
            "raw": "",
        }
