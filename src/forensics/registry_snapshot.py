"""Windows Registry persistence location snapshot.

Captures registry keys commonly used for malware persistence:
- Run/RunOnce keys
- Service registrations
- Scheduled task entries
"""

from __future__ import annotations

import logging
import subprocess
from src.core.subprocess_utils import run_silent
from typing import Any

from src.core.exceptions import ForensicError

logger = logging.getLogger(__name__)

# Registry paths commonly used for persistence
PERSISTENCE_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
]


def capture_registry_persistence() -> dict[str, Any]:
    """Capture registry entries from known persistence locations.

    Returns:
        Dictionary mapping registry paths to their entries.
    """
    result: dict[str, Any] = {}

    for key_path in PERSISTENCE_KEYS:
        try:
            entries = _query_registry_key(key_path)
            result[key_path] = entries
        except ForensicError:
            result[key_path] = {"error": "Access denied or key not found"}
            logger.debug("Could not read registry key: %s", key_path)

    return result


def _query_registry_key(key_path: str) -> list[dict[str, str]]:
    """Query a registry key using reg.exe command.

    Args:
        key_path: Full registry key path (e.g., HKLM\\SOFTWARE\\...).

    Returns:
        List of value entries found under the key.

    Raises:
        ForensicError: If the query fails.
    """
    if not key_path:
        raise ForensicError("Registry key path must not be empty")

    try:
        result = run_silent(["reg", "query", key_path], timeout=10)
    except FileNotFoundError:
        raise ForensicError("reg.exe not found")
    except subprocess.TimeoutExpired:
        raise ForensicError(f"Registry query timed out: {key_path}")

    if result.returncode != 0:
        raise ForensicError(f"Registry query failed for {key_path}: {result.stderr.strip()}")

    return _parse_reg_output(result.stdout)


def _parse_reg_output(output: str) -> list[dict[str, str]]:
    """Parse the output of reg query command.

    Args:
        output: Raw text output from reg query.

    Returns:
        List of dicts with name, type, and value fields.
    """
    entries: list[dict[str, str]] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip key path lines (they start with HKEY_ or HKLM or HKCU)
        is_key_line = line.startswith(("HKEY_", "HKLM", "HKCU"))
        if is_key_line:
            continue

        parts = line.split(None, 2)
        if len(parts) >= 3:
            entries.append({
                "name": parts[0],
                "type": parts[1],
                "value": parts[2],
            })

    return entries


def capture_scheduled_tasks() -> list[dict[str, str]]:
    """Capture scheduled tasks using schtasks command.

    Returns:
        List of scheduled task entries.
    """
    try:
        result = run_silent(["schtasks", "/query", "/fo", "CSV", "/nh"], timeout=30)
    except FileNotFoundError:
        logger.error("schtasks not found")
        return []
    except subprocess.TimeoutExpired:
        logger.error("schtasks query timed out")
        return []

    if result.returncode != 0:
        logger.error("schtasks query failed: %s", result.stderr.strip())
        return []

    tasks: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        line = line.strip().strip('"')
        if not line:
            continue
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 3:
            tasks.append({
                "task_name": parts[0],
                "next_run_time": parts[1],
                "status": parts[2] if len(parts) > 2 else "Unknown",
            })

    return tasks
