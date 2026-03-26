"""Reverse DNS lookup for IP address identification."""

from __future__ import annotations

import logging
import socket
from typing import Any

from src.core.exceptions import IntelError

logger = logging.getLogger(__name__)

DNS_TIMEOUT_SECONDS = 5


def reverse_dns(ip_address: str) -> list[str]:
    """Perform reverse DNS lookup on an IP address.

    Args:
        ip_address: IP address to look up.

    Returns:
        List of hostnames associated with the IP.

    Raises:
        ValueError: If ip_address is empty.
    """
    if not ip_address:
        raise ValueError("ip_address must not be empty")

    try:
        socket.setdefaulttimeout(DNS_TIMEOUT_SECONDS)
        hostname, aliases, _ = socket.gethostbyaddr(ip_address)
        results = [hostname] + list(aliases)
        logger.debug("Reverse DNS for %s: %s", ip_address, results)
        return results
    except socket.herror:
        logger.debug("No reverse DNS entry for %s", ip_address)
        return []
    except socket.gaierror as exc:
        logger.debug("DNS lookup failed for %s: %s", ip_address, exc)
        return []
    except socket.timeout:
        logger.warning("DNS lookup timed out for %s", ip_address)
        return []


def forward_dns(hostname: str) -> list[str]:
    """Perform forward DNS lookup to resolve IPs for a hostname.

    Args:
        hostname: Hostname to resolve.

    Returns:
        List of IP addresses.
    """
    if not hostname:
        raise ValueError("hostname must not be empty")

    try:
        socket.setdefaulttimeout(DNS_TIMEOUT_SECONDS)
        results = socket.getaddrinfo(hostname, None)
        ips = list({result[4][0] for result in results})
        logger.debug("Forward DNS for %s: %s", hostname, ips)
        return ips
    except socket.gaierror as exc:
        logger.debug("Forward DNS failed for %s: %s", hostname, exc)
        return []
    except socket.timeout:
        logger.warning("Forward DNS timed out for %s", hostname)
        return []
