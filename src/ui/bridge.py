"""Thread-safe communication bridge between GUI and detection engine."""

from __future__ import annotations

import queue
import logging
from typing import Any

logger = logging.getLogger(__name__)


class ThreadBridge:
    """Manages thread-safe queues for GUI <-> Engine communication.

    Attributes:
        alert_queue: Engine -> GUI (new alerts, updates).
        status_queue: Engine -> GUI (detector status, forensics/intel results).
        command_queue: GUI -> Engine (user actions).
    """

    def __init__(self, max_size: int = 5000) -> None:
        self.alert_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=max_size)
        self.status_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=max_size)
        self.command_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=max_size)

    def push_alert(self, alert_data: dict[str, Any]) -> None:
        """Push a new alert to the GUI.

        Args:
            alert_data: Alert dictionary.
        """
        self._safe_put(self.alert_queue, {"type": "new_alert", "data": alert_data})

    def push_alert_update(self, alert_uid: str, status: str) -> None:
        """Push an alert status update to the GUI.

        Args:
            alert_uid: Alert unique identifier.
            status: New status string.
        """
        self._safe_put(
            self.alert_queue,
            {"type": "alert_updated", "data": {"alert_uid": alert_uid, "status": status}},
        )

    def push_detector_status(self, statuses: list[dict[str, object]]) -> None:
        """Push detector health statuses to the GUI.

        Args:
            statuses: List of detector health check dicts.
        """
        self._safe_put(self.status_queue, {"type": "detector_status", "data": statuses})

    def push_engine_stats(self, stats: dict[str, Any]) -> None:
        """Push engine statistics to the GUI.

        Args:
            stats: Dict with event_count, queue_size, etc.
        """
        self._safe_put(self.status_queue, {"type": "engine_stats", "data": stats})

    def push_forensic_complete(self, alert_uid: str, evidence_count: int) -> None:
        """Notify GUI that forensic collection is complete.

        Args:
            alert_uid: Alert identifier.
            evidence_count: Number of evidence files collected.
        """
        self._safe_put(
            self.status_queue,
            {"type": "forensic_complete", "data": {"alert_uid": alert_uid, "evidence_count": evidence_count}},
        )

    def push_intel_complete(self, alert_uid: str, intel_data: dict[str, Any]) -> None:
        """Notify GUI that intel enrichment is complete.

        Args:
            alert_uid: Alert identifier.
            intel_data: Intel result dictionary.
        """
        self._safe_put(
            self.status_queue,
            {"type": "intel_complete", "data": {"alert_uid": alert_uid, "intel": intel_data}},
        )

    def push_response_result(
        self, alert_uid: str, success: bool, message: str
    ) -> None:
        """Push response action result to the GUI.

        Args:
            alert_uid: Alert identifier.
            success: Whether the action succeeded.
            message: Result message.
        """
        self._safe_put(
            self.status_queue,
            {"type": "response_result", "data": {"alert_uid": alert_uid, "success": success, "message": message}},
        )

    def push_log(self, level: str, message: str) -> None:
        """Push a log message to the GUI.

        Args:
            level: Log level (INFO, WARNING, ERROR).
            message: Log message.
        """
        self._safe_put(
            self.status_queue,
            {"type": "log_message", "data": {"level": level, "message": message}},
        )

    def send_command(self, command_type: str, data: dict[str, Any] | None = None) -> None:
        """Send a command from GUI to Engine.

        Args:
            command_type: Command type string.
            data: Command payload.
        """
        self._safe_put(self.command_queue, {"type": command_type, "data": data or {}})

    @staticmethod
    def _safe_put(q: queue.Queue[dict[str, Any]], msg: dict[str, Any]) -> None:
        """Put a message on a queue, dropping if full.

        Args:
            q: Target queue.
            msg: Message to enqueue.
        """
        try:
            q.put_nowait(msg)
        except queue.Full:
            logger.warning("Queue full, dropping message: %s", msg.get("type"))
