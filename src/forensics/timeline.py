"""Event timeline reconstruction for forensic analysis.

Builds a chronological timeline from correlated events
to aid in understanding the attack sequence.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from src.core.models import Alert, RawEvent

logger = logging.getLogger(__name__)


def build_timeline(
    alert: Alert,
    correlated_events: list[RawEvent],
) -> list[dict[str, Any]]:
    """Build a chronological timeline from an alert and its correlated events.

    Args:
        alert: The primary alert.
        correlated_events: List of correlated RawEvents.

    Returns:
        Sorted list of timeline entries.
    """
    entries: list[dict[str, Any]] = []

    entries.append(_event_to_timeline_entry(
        alert.raw_event,
        is_primary=True,
        alert_title=alert.title,
    ))

    for event in correlated_events:
        entries.append(_event_to_timeline_entry(event, is_primary=False))

    entries.sort(key=lambda e: e["timestamp"])

    for idx, entry in enumerate(entries):
        entry["sequence_number"] = idx + 1

    return entries


def _event_to_timeline_entry(
    event: RawEvent,
    is_primary: bool = False,
    alert_title: str | None = None,
) -> dict[str, Any]:
    """Convert a RawEvent to a timeline entry.

    Args:
        event: The raw event.
        is_primary: Whether this is the primary (triggering) event.
        alert_title: Title from the alert if this is the primary event.

    Returns:
        Timeline entry dictionary.
    """
    rule = event.data.get("rule", "unknown")
    description = _describe_event(event, rule)

    return {
        "timestamp": event.timestamp,
        "event_uid": event.event_uid,
        "event_type": event.event_type.value,
        "rule": rule,
        "description": description,
        "is_primary": is_primary,
        "alert_title": alert_title,
        "source_ip": event.source_ip,
        "dest_ip": event.dest_ip,
        "process_name": event.process_name,
        "process_pid": event.process_pid,
        "file_path": event.file_path,
    }


def _describe_event(event: RawEvent, rule: str) -> str:
    """Generate a human-readable description of an event.

    Args:
        event: The raw event.
        rule: The scoring rule name.

    Returns:
        Description string.
    """
    descriptions = {
        "known_malware_name": (
            f"Suspicious process detected: {event.process_name} (PID {event.process_pid})"
        ),
        "suspicious_parent_child": (
            f"Suspicious process chain: {event.data.get('parent_name', '?')} "
            f"-> {event.process_name}"
        ),
        "suspicious_port_connection": (
            f"Connection to suspicious port: {event.dest_ip}:{event.dest_port}"
        ),
        "new_listening_port": (
            f"New listening port opened: {event.dest_ip}:{event.dest_port}"
        ),
        "log_clearing": "Security log was cleared",
        "new_service_installed": (
            f"New service installed: {event.data.get('service_name', 'Unknown')}"
        ),
        "multiple_failed_logins": (
            f"Multiple failed login attempts from {event.source_ip}"
        ),
        "filesystem_change_system32": (
            f"File change in system directory: {event.file_path}"
        ),
        "suricata_high_severity": (
            f"Suricata alert: {event.data.get('signature', 'Unknown')}"
        ),
        "suricata_medium_severity": (
            f"Suricata alert: {event.data.get('signature', 'Unknown')}"
        ),
    }

    return descriptions.get(rule, f"Event detected: {rule} ({event.event_type.value})")
