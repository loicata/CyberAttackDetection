"""Traceroute to identify network path to an IP address."""

from __future__ import annotations

import logging
import subprocess
from src.core.subprocess_utils import run_silent
from typing import Any

logger = logging.getLogger(__name__)

TRACEROUTE_TIMEOUT_SECONDS = 60
MAX_HOPS = 30


def traceroute(ip_address: str, max_hops: int = MAX_HOPS) -> list[dict[str, Any]]:
    """Run traceroute (tracert on Windows) to an IP address.

    Args:
        ip_address: Target IP address.
        max_hops: Maximum number of hops.

    Returns:
        List of hop dictionaries with hop number, IP, and RTT.

    Raises:
        ValueError: If ip_address is empty.
    """
    if not ip_address:
        raise ValueError("ip_address must not be empty")

    if not isinstance(max_hops, int) or not (1 <= max_hops <= 64):
        raise ValueError(f"max_hops must be 1-64, got {max_hops}")

    try:
        result = run_silent(
            ["tracert", "-d", "-h", str(max_hops), "-w", "1000", ip_address],
            timeout=TRACEROUTE_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        logger.error("tracert command not found")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("Traceroute timed out for %s", ip_address)
        return []

    return _parse_tracert_output(result.stdout)


def _parse_tracert_output(output: str) -> list[dict[str, Any]]:
    """Parse Windows tracert output.

    Args:
        output: Raw tracert output text.

    Returns:
        List of parsed hop entries.
    """
    hops: list[dict[str, Any]] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Tracert lines start with hop number
        parts = line.split()
        if not parts or not parts[0].isdigit():
            continue

        hop_num = int(parts[0])
        ip_address = None
        rtts: list[str] = []

        for part in parts[1:]:
            if _looks_like_ip(part):
                ip_address = part
            elif part.endswith("ms"):
                rtts.append(part)
            elif part == "*":
                rtts.append("*")

        hops.append({
            "hop": hop_num,
            "ip": ip_address,
            "rtts": rtts,
            "timeout": ip_address is None,
        })

    return hops


def _looks_like_ip(text: str) -> bool:
    """Check if a string looks like an IP address.

    Args:
        text: String to check.

    Returns:
        True if it looks like an IP.
    """
    parts = text.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
