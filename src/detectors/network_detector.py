"""Network connection monitor using psutil.

Detects:
- Connections to suspicious ports
- New listening ports
- Sudden spikes in connection count
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


class NetworkDetector(BaseDetector):
    """Monitor network connections for suspicious activity.

    Args:
        event_bus: Event bus to publish detected events.
        config: Application configuration.
    """

    def __init__(self, event_bus: EventBus, config: AppConfig) -> None:
        super().__init__(
            name="network_detector",
            event_bus=event_bus,
            polling_interval=config.polling_interval_seconds,
        )
        self._config = config
        self._suspicious_ports = set(config.suspicious_ports)
        self._known_listening: set[tuple[str, int]] = set()
        self._known_connections: set[tuple[str, int, str, int]] = set()
        self._connection_counts: list[int] = []
        self._max_history = 12  # Track last 12 cycles for spike detection

    async def _initialize(self) -> None:
        """Capture initial connection state."""
        connections = await asyncio.to_thread(self._get_connections)
        self._known_listening = self._extract_listening(connections)
        self._known_connections = self._extract_established(connections)
        logger.info(
            "Network detector initialized: %d listening, %d established",
            len(self._known_listening),
            len(self._known_connections),
        )

    async def _poll(self) -> list[RawEvent]:
        """Check for new or suspicious network connections.

        Returns:
            List of RawEvent for suspicious network activity.
        """
        connections = await asyncio.to_thread(self._get_connections)
        events: list[RawEvent] = []

        events.extend(self._check_listening(connections))
        events.extend(self._check_established(connections))
        events.extend(self._check_connection_spike(connections))

        current_listening = self._extract_listening(connections)
        current_established = self._extract_established(connections)
        self._known_listening = current_listening
        self._known_connections = current_established

        return events

    def _check_listening(self, connections: list[dict[str, Any]]) -> list[RawEvent]:
        """Detect new listening ports.

        Args:
            connections: Current connection snapshot.

        Returns:
            Events for newly opened listening ports.
        """
        events: list[RawEvent] = []
        current_listening = self._extract_listening(connections)
        new_listening = current_listening - self._known_listening

        for addr, port in new_listening:
            events.append(
                RawEvent(
                    event_type=AlertType.NETWORK,
                    data={
                        "rule": "new_listening_port",
                        "local_address": addr,
                        "local_port": port,
                        "status": "LISTEN",
                    },
                    dest_ip=addr,
                    dest_port=port,
                )
            )
            logger.info("New listening port detected: %s:%d", addr, port)

        return events

    def _check_established(self, connections: list[dict[str, Any]]) -> list[RawEvent]:
        """Detect connections to suspicious ports.

        Args:
            connections: Current connection snapshot.

        Returns:
            Events for connections to suspicious ports.
        """
        events: list[RawEvent] = []

        for conn in connections:
            status = conn.get("status", "")
            if status != "ESTABLISHED":
                continue

            remote_port = conn.get("remote_port", 0)
            remote_addr = conn.get("remote_address", "")

            is_suspicious_port = remote_port in self._suspicious_ports
            if not is_suspicious_port:
                continue

            conn_key = (
                conn.get("local_address", ""),
                conn.get("local_port", 0),
                remote_addr,
                remote_port,
            )
            is_new_connection = conn_key not in self._known_connections
            if not is_new_connection:
                continue

            events.append(
                RawEvent(
                    event_type=AlertType.NETWORK,
                    data={
                        "rule": "suspicious_port_connection",
                        "connection": conn,
                    },
                    source_ip=conn.get("local_address"),
                    source_port=conn.get("local_port"),
                    dest_ip=remote_addr,
                    dest_port=remote_port,
                    process_pid=conn.get("pid"),
                    process_name=conn.get("process_name"),
                )
            )
            logger.warning(
                "Suspicious port connection: %s:%d -> %s:%d (PID %s)",
                conn.get("local_address"),
                conn.get("local_port", 0),
                remote_addr,
                remote_port,
                conn.get("pid"),
            )

        return events

    def _check_connection_spike(
        self, connections: list[dict[str, Any]]
    ) -> list[RawEvent]:
        """Detect sudden spikes in total connection count.

        Args:
            connections: Current connection snapshot.

        Returns:
            Events if connection count exceeds threshold.
        """
        events: list[RawEvent] = []
        current_count = len(connections)
        self._connection_counts.append(current_count)

        if len(self._connection_counts) > self._max_history:
            self._connection_counts = self._connection_counts[-self._max_history:]

        has_enough_history = len(self._connection_counts) >= 3
        if not has_enough_history:
            return events

        avg = sum(self._connection_counts[:-1]) / len(self._connection_counts[:-1])
        spike_threshold = max(avg * 3, 100)
        is_spike = current_count > spike_threshold

        if is_spike:
            events.append(
                RawEvent(
                    event_type=AlertType.NETWORK,
                    data={
                        "rule": "connection_spike",
                        "current_count": current_count,
                        "average_count": round(avg, 1),
                        "threshold": round(spike_threshold, 1),
                    },
                )
            )
            logger.warning(
                "Connection spike detected: %d (avg %.1f, threshold %.1f)",
                current_count,
                avg,
                spike_threshold,
            )

        return events

    @staticmethod
    def _extract_listening(
        connections: list[dict[str, Any]],
    ) -> set[tuple[str, int]]:
        """Extract listening address:port pairs.

        Args:
            connections: Connection snapshot.

        Returns:
            Set of (address, port) tuples for listening sockets.
        """
        return {
            (c["local_address"], c["local_port"])
            for c in connections
            if c.get("status") == "LISTEN"
        }

    @staticmethod
    def _extract_established(
        connections: list[dict[str, Any]],
    ) -> set[tuple[str, int, str, int]]:
        """Extract established connection tuples.

        Args:
            connections: Connection snapshot.

        Returns:
            Set of (local_addr, local_port, remote_addr, remote_port).
        """
        return {
            (
                c["local_address"],
                c["local_port"],
                c.get("remote_address", ""),
                c.get("remote_port", 0),
            )
            for c in connections
            if c.get("status") == "ESTABLISHED"
        }

    @staticmethod
    def _get_connections() -> list[dict[str, Any]]:
        """Get all current network connections.

        Returns:
            List of connection info dictionaries.
        """
        results: list[dict[str, Any]] = []

        for conn in psutil.net_connections(kind="inet"):
            local_addr = conn.laddr.ip if conn.laddr else ""
            local_port = conn.laddr.port if conn.laddr else 0
            remote_addr = conn.raddr.ip if conn.raddr else ""
            remote_port = conn.raddr.port if conn.raddr else 0

            proc_name = None
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            results.append({
                "local_address": local_addr,
                "local_port": local_port,
                "remote_address": remote_addr,
                "remote_port": remote_port,
                "status": conn.status,
                "pid": conn.pid,
                "process_name": proc_name,
                "family": str(conn.family),
            })

        return results
