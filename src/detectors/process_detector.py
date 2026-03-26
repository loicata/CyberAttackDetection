"""Process monitor detector using psutil.

Detects:
- New processes with suspicious names
- Suspicious parent-child process chains
- Processes with abnormal CPU/memory usage
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import psutil

from src.core.config import AppConfig
from src.core.enums import AlertType
from src.core.event_bus import EventBus
from src.core.models import RawEvent
from src.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class ProcessDetector(BaseDetector):
    """Monitor running processes for suspicious activity.

    Args:
        event_bus: Event bus to publish detected events.
        config: Application configuration.
    """

    def __init__(self, event_bus: EventBus, config: AppConfig) -> None:
        super().__init__(
            name="process_detector",
            event_bus=event_bus,
            polling_interval=config.polling_interval_seconds,
        )
        self._config = config
        self._suspicious_names = {
            n.lower() for n in config.suspicious_process_names
        }
        self._suspicious_parent_child = {
            (p.lower(), c.lower()) for p, c in config.suspicious_parent_child
        }
        self._known_pids: set[int] = set()
        self._process_cache: dict[int, str] = {}

    async def _initialize(self) -> None:
        """Capture initial process snapshot to avoid alerting on existing processes."""
        snapshot = await asyncio.to_thread(self._snapshot_processes)
        self._known_pids = {p["pid"] for p in snapshot}
        self._process_cache = {p["pid"]: p["name"] for p in snapshot}
        logger.info(
            "Process detector initialized with %d existing processes",
            len(self._known_pids),
        )

    async def _poll(self) -> list[RawEvent]:
        """Check for new or suspicious processes.

        Returns:
            List of RawEvent for any suspicious process activity.
        """
        current_snapshot = await asyncio.to_thread(self._snapshot_processes)
        events: list[RawEvent] = []

        current_pids = {p["pid"] for p in current_snapshot}
        new_pids = current_pids - self._known_pids

        for proc_info in current_snapshot:
            pid = proc_info["pid"]
            name_lower = proc_info["name"].lower() if proc_info["name"] else ""

            if pid in new_pids:
                events.extend(self._check_new_process(proc_info, name_lower))

            events.extend(self._check_resource_usage(proc_info))

        self._known_pids = current_pids
        self._process_cache = {p["pid"]: p["name"] for p in current_snapshot}

        return events

    def _check_new_process(
        self, proc_info: dict[str, Any], name_lower: str
    ) -> list[RawEvent]:
        """Check a newly appeared process for suspicious indicators.

        Args:
            proc_info: Process information dictionary.
            name_lower: Lowercased process name.

        Returns:
            List of events if suspicious, empty otherwise.
        """
        events: list[RawEvent] = []

        name_without_ext = name_lower.rsplit(".", 1)[0] if "." in name_lower else name_lower
        is_suspicious_name = (
            name_lower in self._suspicious_names
            or name_without_ext in self._suspicious_names
        )
        if is_suspicious_name:
            events.append(
                RawEvent(
                    event_type=AlertType.PROCESS,
                    data={
                        "rule": "known_malware_name",
                        "process": proc_info,
                    },
                    process_name=proc_info.get("name"),
                    process_pid=proc_info.get("pid"),
                )
            )
            logger.warning(
                "Suspicious process detected: %s (PID %d)",
                proc_info.get("name"),
                proc_info.get("pid", 0),
            )

        parent_name = self._get_parent_name(proc_info)
        if parent_name:
            pair = (parent_name.lower(), name_lower)
            is_suspicious_chain = pair in self._suspicious_parent_child
            if is_suspicious_chain:
                events.append(
                    RawEvent(
                        event_type=AlertType.PROCESS,
                        data={
                            "rule": "suspicious_parent_child",
                            "parent_name": parent_name,
                            "child_name": proc_info.get("name"),
                            "process": proc_info,
                        },
                        process_name=proc_info.get("name"),
                        process_pid=proc_info.get("pid"),
                    )
                )
                logger.warning(
                    "Suspicious parent-child: %s -> %s (PID %d)",
                    parent_name,
                    proc_info.get("name"),
                    proc_info.get("pid", 0),
                )

        return events

    def _check_resource_usage(self, proc_info: dict[str, Any]) -> list[RawEvent]:
        """Check if a process has abnormal resource consumption.

        Args:
            proc_info: Process information dictionary.

        Returns:
            List of events if resource usage is abnormal.
        """
        events: list[RawEvent] = []
        cpu = proc_info.get("cpu_percent", 0.0)
        mem_mb = proc_info.get("memory_mb", 0.0)

        raw_config = self._config.raw.get("detection", {}).get("process", {})
        cpu_threshold = raw_config.get("max_cpu_threshold_percent", 95.0)
        mem_threshold = raw_config.get("max_memory_threshold_mb", 4096)

        if cpu > cpu_threshold:
            events.append(
                RawEvent(
                    event_type=AlertType.PROCESS,
                    data={
                        "rule": "process_high_cpu",
                        "cpu_percent": cpu,
                        "threshold": cpu_threshold,
                        "process": proc_info,
                    },
                    process_name=proc_info.get("name"),
                    process_pid=proc_info.get("pid"),
                )
            )

        if mem_mb > mem_threshold:
            events.append(
                RawEvent(
                    event_type=AlertType.PROCESS,
                    data={
                        "rule": "process_high_memory",
                        "memory_mb": mem_mb,
                        "threshold": mem_threshold,
                        "process": proc_info,
                    },
                    process_name=proc_info.get("name"),
                    process_pid=proc_info.get("pid"),
                )
            )

        return events

    def _get_parent_name(self, proc_info: dict[str, Any]) -> str | None:
        """Resolve parent process name from cache.

        Args:
            proc_info: Process info with ppid field.

        Returns:
            Parent process name or None.
        """
        ppid = proc_info.get("ppid")
        if ppid is None:
            return None
        return self._process_cache.get(ppid)

    @staticmethod
    def _snapshot_processes() -> list[dict[str, Any]]:
        """Take a snapshot of all running processes.

        Returns:
            List of process info dictionaries. Processes that cannot
            be accessed (permission errors) are silently skipped.
        """
        processes: list[dict[str, Any]] = []
        attrs = ["pid", "name", "ppid", "exe", "username", "cpu_percent",
                 "memory_info", "create_time", "cmdline"]

        for proc in psutil.process_iter(attrs=attrs):
            try:
                info = proc.info  # type: ignore[attr-defined]
                mem_info = info.get("memory_info")
                memory_mb = mem_info.rss / (1024 * 1024) if mem_info else 0.0

                processes.append({
                    "pid": info.get("pid", 0),
                    "name": info.get("name", ""),
                    "ppid": info.get("ppid"),
                    "exe": info.get("exe"),
                    "username": info.get("username"),
                    "cpu_percent": info.get("cpu_percent", 0.0),
                    "memory_mb": round(memory_mb, 2),
                    "create_time": info.get("create_time"),
                    "cmdline": info.get("cmdline"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return processes
