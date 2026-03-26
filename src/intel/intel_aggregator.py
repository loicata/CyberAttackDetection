"""Combine all threat intelligence sources into a unified report."""

from __future__ import annotations

import logging
from typing import Any

from src.core.config import AppConfig
from src.core.models import IntelResult
from src.intel.dns_lookup import reverse_dns
from src.intel.whois_lookup import whois_lookup
from src.intel.geoip import geoip_lookup
from src.intel.traceroute import traceroute
from src.intel.osint import abuseipdb_check, virustotal_check

logger = logging.getLogger(__name__)


def gather_intel(ip_address: str, config: AppConfig) -> IntelResult:
    """Gather all available intelligence on an IP address.

    Runs all enabled intel sources and combines results.
    Failures in individual sources do not prevent others from running.

    Args:
        ip_address: The IP address to investigate.
        config: Application configuration.

    Returns:
        Combined IntelResult with all gathered data.

    Raises:
        ValueError: If ip_address is empty.
    """
    if not ip_address:
        raise ValueError("ip_address must not be empty")

    logger.info("Gathering intelligence on %s", ip_address)

    # Reverse DNS
    dns_results = _safe_call("Reverse DNS", reverse_dns, ip_address)

    # WHOIS
    whois_data = _safe_call("WHOIS", whois_lookup, ip_address)

    # GeoIP
    geo_data = _safe_call(
        "GeoIP",
        geoip_lookup,
        ip_address,
        timeout=config.intel.request_timeout_seconds,
    )

    # Traceroute
    trace_hops = _safe_call("Traceroute", traceroute, ip_address)

    # OSINT: AbuseIPDB
    abuse_data: dict[str, Any] = {}
    if config.intel.abuseipdb_enabled:
        abuse_data = _safe_call(
            "AbuseIPDB",
            abuseipdb_check,
            ip_address,
            timeout=config.intel.request_timeout_seconds,
        )

    # OSINT: VirusTotal
    vt_data: dict[str, Any] = {}
    if config.intel.virustotal_enabled:
        vt_data = _safe_call(
            "VirusTotal",
            virustotal_check,
            ip_address,
            timeout=config.intel.request_timeout_seconds,
        )

    result = IntelResult(
        ip_address=ip_address,
        reverse_dns=dns_results if isinstance(dns_results, list) else [],
        whois_org=whois_data.get("organization") if isinstance(whois_data, dict) else None,
        whois_country=whois_data.get("country") if isinstance(whois_data, dict) else None,
        whois_raw=whois_data.get("raw") if isinstance(whois_data, dict) else None,
        geoip_country=geo_data.get("country") if isinstance(geo_data, dict) else None,
        geoip_city=geo_data.get("city") if isinstance(geo_data, dict) else None,
        geoip_lat=geo_data.get("latitude") if isinstance(geo_data, dict) else None,
        geoip_lon=geo_data.get("longitude") if isinstance(geo_data, dict) else None,
        abuse_score=(
            abuse_data.get("abuse_confidence_score")
            if isinstance(abuse_data, dict)
            else None
        ),
        abuse_reports=(
            abuse_data.get("total_reports")
            if isinstance(abuse_data, dict)
            else None
        ),
        virustotal_malicious=(
            vt_data.get("malicious") if isinstance(vt_data, dict) else None
        ),
        virustotal_total=(
            (
                vt_data.get("malicious", 0)
                + vt_data.get("suspicious", 0)
                + vt_data.get("harmless", 0)
                + vt_data.get("undetected", 0)
            )
            if isinstance(vt_data, dict) and vt_data.get("available")
            else None
        ),
        traceroute_hops=trace_hops if isinstance(trace_hops, list) else [],
    )

    logger.info(
        "Intel gathered for %s: DNS=%d, WHOIS=%s, GeoIP=%s, Traceroute=%d hops",
        ip_address,
        len(result.reverse_dns),
        result.whois_org or "N/A",
        result.geoip_country or "N/A",
        len(result.traceroute_hops),
    )

    return result


def _safe_call(source_name: str, func: Any, *args: Any, **kwargs: Any) -> Any:
    """Call a function and catch any exception.

    Args:
        source_name: Name of the intel source (for logging).
        func: Function to call.
        *args: Positional arguments.
        **kwargs: Keyword arguments.

    Returns:
        Function result, or empty dict/list on failure.
    """
    try:
        return func(*args, **kwargs)
    except Exception:
        logger.exception("Intel source %s failed", source_name)
        return {}
