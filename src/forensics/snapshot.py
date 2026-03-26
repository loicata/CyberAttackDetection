"""System state capture for forensic analysis.

Captures processes, network connections, services, and loaded DLLs
at the time of alert detection.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import psutil

from src.core.exceptions import ForensicError

logger = logging.getLogger(__name__)


async def capture_system_snapshot() -> dict[str, Any]:
    """Capture a full system state snapshot.

    Returns:
        Dictionary containing processes, connections, and system info.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    processes = await asyncio.to_thread(_capture_processes)
    connections = await asyncio.to_thread(_capture_connections)
    system_info = await asyncio.to_thread(_capture_system_info)

    return {
        "timestamp": timestamp,
        "system_info": system_info,
        "process_count": len(processes),
        "connection_count": len(connections),
    }


async def capture_process_list() -> list[dict[str, Any]]:
    """Capture detailed process list.

    Returns:
        List of process info dictionaries.
    """
    return await asyncio.to_thread(_capture_processes)


async def capture_network_connections() -> list[dict[str, Any]]:
    """Capture all active network connections.

    Returns:
        List of connection info dictionaries.
    """
    return await asyncio.to_thread(_capture_connections)


async def capture_process_details(pid: int) -> dict[str, Any] | None:
    """Capture detailed info about a specific process.

    Args:
        pid: Process ID to inspect.

    Returns:
        Detailed process info or None if not found.
    """
    return await asyncio.to_thread(_capture_single_process, pid)


def _capture_processes() -> list[dict[str, Any]]:
    """Capture all running processes with detailed attributes."""
    processes: list[dict[str, Any]] = []
    attrs = [
        "pid", "name", "ppid", "exe", "cmdline", "username",
        "create_time", "cpu_percent", "memory_info", "status",
        "num_threads",
    ]

    for proc in psutil.process_iter(attrs=attrs):
        try:
            info = proc.info  # type: ignore[attr-defined]
            mem = info.get("memory_info")
            processes.append({
                "pid": info.get("pid"),
                "name": info.get("name"),
                "ppid": info.get("ppid"),
                "exe": info.get("exe"),
                "cmdline": info.get("cmdline"),
                "username": info.get("username"),
                "create_time": info.get("create_time"),
                "cpu_percent": info.get("cpu_percent"),
                "memory_rss_bytes": mem.rss if mem else 0,
                "memory_vms_bytes": mem.vms if mem else 0,
                "status": info.get("status"),
                "num_threads": info.get("num_threads"),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return processes


def _capture_connections() -> list[dict[str, Any]]:
    """Capture all network connections."""
    results: list[dict[str, Any]] = []

    for conn in psutil.net_connections(kind="inet"):
        results.append({
            "fd": conn.fd,
            "family": str(conn.family),
            "type": str(conn.type),
            "local_address": conn.laddr.ip if conn.laddr else "",
            "local_port": conn.laddr.port if conn.laddr else 0,
            "remote_address": conn.raddr.ip if conn.raddr else "",
            "remote_port": conn.raddr.port if conn.raddr else 0,
            "status": conn.status,
            "pid": conn.pid,
        })

    return results


def _capture_system_info() -> dict[str, Any]:
    """Capture basic system information."""
    import platform

    boot_time = datetime.fromtimestamp(
        psutil.boot_time(), tz=timezone.utc
    ).isoformat()

    return {
        "platform": platform.platform(),
        "hostname": platform.node(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "boot_time": boot_time,
        "cpu_count": psutil.cpu_count(),
        "memory_total_bytes": psutil.virtual_memory().total,
    }


def _capture_single_process(pid: int) -> dict[str, Any] | None:
    """Capture detailed info for a single process including DLLs."""
    try:
        proc = psutil.Process(pid)
        info = proc.as_dict(attrs=[
            "pid", "name", "ppid", "exe", "cmdline", "username",
            "create_time", "cpu_percent", "memory_info", "status",
            "num_threads", "environ",
        ])

        # Capture loaded modules (DLLs on Windows)
        memory_maps: list[str] = []
        try:
            for mmap in proc.memory_maps():
                memory_maps.append(mmap.path)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        mem = info.get("memory_info")
        return {
            "pid": info.get("pid"),
            "name": info.get("name"),
            "ppid": info.get("ppid"),
            "exe": info.get("exe"),
            "cmdline": info.get("cmdline"),
            "username": info.get("username"),
            "create_time": info.get("create_time"),
            "cpu_percent": info.get("cpu_percent"),
            "memory_rss_bytes": mem.rss if mem else 0,
            "memory_vms_bytes": mem.vms if mem else 0,
            "status": info.get("status"),
            "num_threads": info.get("num_threads"),
            "environ": info.get("environ"),
            "loaded_modules": memory_maps,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None
