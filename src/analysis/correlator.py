"""Multi-signal event correlator.

Detects attack patterns by correlating events across different
detectors within a sliding time window.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any

from src.core.config import AppConfig
from src.core.enums import AlertType
from src.core.models import RawEvent

logger = logging.getLogger(__name__)


# Correlation patterns: (name, required event types, description)
CORRELATION_PATTERNS: list[tuple[str, list[str], str]] = [
    (
        "potential_c2",
        ["PROCESS_new", "NETWORK_suspicious"],
        "New process followed by suspicious outbound connection (potential C2)",
    ),
    (
        "brute_force_success",
        ["EVENTLOG_failed_login", "EVENTLOG_success_login"],
        "Multiple failed logins followed by successful login (brute force)",
    ),
    (
        "persistence_install",
        ["FILESYSTEM_created", "EVENTLOG_service"],
        "File creation in startup + new service installation (persistence)",
    ),
    (
        "cover_up",
        ["EVENTLOG_log_clear", "ANY_suspicious"],
        "Log clearing combined with other suspicious activity (cover-up)",
    ),
    # Sysmon-enriched patterns
    (
        "code_injection",
        ["EVENTLOG_remote_thread", "ANY_suspicious"],
        "CreateRemoteThread detected with other suspicious activity (code injection)",
    ),
    (
        "credential_theft",
        ["EVENTLOG_lsass", "ANY_suspicious"],
        "LSASS access combined with suspicious activity (credential theft)",
    ),
    (
        "process_tampering_chain",
        ["EVENTLOG_tampering", "ANY_suspicious"],
        "Process tampering with other suspicious activity (evasion technique)",
    ),
    (
        "lateral_movement",
        ["EVENTLOG_remote_thread", "NETWORK_suspicious"],
        "Code injection + suspicious network connection (lateral movement)",
    ),
    (
        "sysmon_persistence_chain",
        ["EVENTLOG_registry_persist", "EVENTLOG_startup"],
        "Registry persistence + startup file creation (multi-layer persistence)",
    ),
]


class EventCorrelator:
    """Correlate events across detectors to identify attack patterns.

    Maintains a sliding window of recent events and looks for
    multi-signal patterns that indicate coordinated attacks.

    Args:
        config: Application configuration.
    """

    def __init__(self, config: AppConfig) -> None:
        self._window_seconds = config.analysis.correlation_window_seconds
        self._events: list[tuple[float, RawEvent, str]] = []

    def add_event(self, event: RawEvent) -> list[CorrelationMatch]:
        """Add an event and check for new correlations.

        Args:
            event: The raw event to add.

        Returns:
            List of CorrelationMatch objects for any patterns detected.
        """
        now = time.monotonic()
        self._expire_old_events(now)

        event_tag = self._tag_event(event)
        self._events.append((now, event, event_tag))

        matches = self._check_patterns(event, event_tag)
        return matches

    def has_recent_correlation(self, event: RawEvent) -> bool:
        """Check if this event correlates with any recent events.

        Args:
            event: The event to check.

        Returns:
            True if correlations are found.
        """
        matches = self.add_event(event)
        return len(matches) > 0

    def get_correlated_uids(self, event: RawEvent) -> list[str]:
        """Get UIDs of events that correlate with this one.

        Args:
            event: The event to find correlations for.

        Returns:
            List of correlated event UIDs.
        """
        now = time.monotonic()
        self._expire_old_events(now)

        uids: list[str] = []
        event_tag = self._tag_event(event)

        for _, stored_event, stored_tag in self._events:
            if stored_event.event_uid == event.event_uid:
                continue
            is_related = self._are_related(event, event_tag, stored_event, stored_tag)
            if is_related:
                uids.append(stored_event.event_uid)

        return uids

    def _check_patterns(
        self, new_event: RawEvent, new_tag: str
    ) -> list[CorrelationMatch]:
        """Check all correlation patterns against the current window.

        Args:
            new_event: The newly added event.
            new_tag: The tag for the new event.

        Returns:
            List of matched patterns.
        """
        matches: list[CorrelationMatch] = []

        tags_in_window = {tag for _, _, tag in self._events}

        for pattern_name, required_tags, description in CORRELATION_PATTERNS:
            pattern_matched = self._pattern_matches(
                required_tags, tags_in_window, new_tag
            )
            if pattern_matched:
                involved_uids = [
                    ev.event_uid
                    for _, ev, tag in self._events
                    if self._tag_matches_any(tag, required_tags)
                ]
                matches.append(
                    CorrelationMatch(
                        pattern_name=pattern_name,
                        description=description,
                        involved_event_uids=involved_uids,
                    )
                )
                logger.warning(
                    "Correlation pattern matched: %s (%d events)",
                    pattern_name,
                    len(involved_uids),
                )

        return matches

    def _pattern_matches(
        self,
        required_tags: list[str],
        tags_in_window: set[str],
        new_tag: str,
    ) -> bool:
        """Check if all required tags for a pattern are present.

        Args:
            required_tags: Tags required by the pattern.
            tags_in_window: All tags currently in the window.
            new_tag: Tag of the newly added event.

        Returns:
            True if all required tags are satisfied.
        """
        for req_tag in required_tags:
            if req_tag.startswith("ANY_"):
                has_any_match = any(
                    t for t in tags_in_window if "suspicious" in t or "malware" in t
                )
                if not has_any_match:
                    return False
            else:
                has_match = any(t.startswith(req_tag) or t == req_tag for t in tags_in_window)
                if not has_match:
                    return False
        return True

    def _are_related(
        self,
        event_a: RawEvent,
        tag_a: str,
        event_b: RawEvent,
        tag_b: str,
    ) -> bool:
        """Check if two events are related (same source or same target).

        Args:
            event_a: First event.
            tag_a: Tag of first event.
            event_b: Second event.
            tag_b: Tag of second event.

        Returns:
            True if events share source IP, dest IP, or process.
        """
        same_source = (
            event_a.source_ip
            and event_b.source_ip
            and event_a.source_ip == event_b.source_ip
        )
        same_dest = (
            event_a.dest_ip
            and event_b.dest_ip
            and event_a.dest_ip == event_b.dest_ip
        )
        same_process = (
            event_a.process_name
            and event_b.process_name
            and event_a.process_name == event_b.process_name
        )

        return bool(same_source or same_dest or same_process)

    def _tag_event(self, event: RawEvent) -> str:
        """Generate a classification tag for an event.

        Args:
            event: The raw event.

        Returns:
            A string tag like "PROCESS_new" or "EVENTLOG_log_clear".
        """
        rule = event.data.get("rule", "unknown")
        event_type = event.event_type.value

        if rule == "known_malware_name":
            return f"{event_type}_malware"
        if rule == "suspicious_parent_child":
            return f"{event_type}_suspicious"
        if rule in ("suspicious_port_connection", "new_listening_port"):
            return f"{event_type}_suspicious"
        if rule == "log_clearing":
            return "EVENTLOG_log_clear"
        if rule == "multiple_failed_logins":
            return "EVENTLOG_failed_login"
        if rule == "eventlog_critical_event":
            event_id = event.data.get("event_id")
            if event_id == 4624:
                return "EVENTLOG_success_login"
            return f"{event_type}_critical"
        if rule == "new_service_installed":
            return "EVENTLOG_service"
        if rule == "filesystem_change_system32":
            return "FILESYSTEM_created"
        if rule in ("suricata_high_severity", "suricata_medium_severity"):
            return f"{event_type}_suspicious"

        # Sysmon-specific tags for correlation
        if rule == "sysmon_create_remote_thread":
            return "EVENTLOG_remote_thread"
        if rule == "sysmon_lsass_access":
            return "EVENTLOG_lsass"
        if rule == "sysmon_process_tampering":
            return "EVENTLOG_tampering"
        if rule == "sysmon_registry_persistence":
            return "EVENTLOG_registry_persist"
        if rule == "sysmon_startup_file_create":
            return "EVENTLOG_startup"
        if rule in ("sysmon_suspicious_network", "sysmon_suspicious_dns",
                     "sysmon_dns_tunneling", "sysmon_encoded_powershell",
                     "sysmon_suspicious_pipe", "sysmon_suspicious_dll_load",
                     "sysmon_suspicious_exec_path", "sysmon_ads_created"):
            return f"{event_type}_suspicious"

        if "new" in rule:
            return f"{event_type}_new"

        return f"{event_type}_{rule}"

    def _tag_matches_any(self, tag: str, required_tags: list[str]) -> bool:
        """Check if a tag matches any of the required tags.

        Args:
            tag: The tag to check.
            required_tags: List of required tag patterns.

        Returns:
            True if the tag matches any required tag.
        """
        for req in required_tags:
            if req.startswith("ANY_"):
                if "suspicious" in tag or "malware" in tag:
                    return True
            elif tag.startswith(req) or tag == req:
                return True
        return False

    def _expire_old_events(self, now: float) -> None:
        """Remove events outside the correlation window.

        Args:
            now: Current monotonic time.
        """
        cutoff = now - self._window_seconds
        self._events = [
            (t, e, tag) for t, e, tag in self._events if t > cutoff
        ]


class CorrelationMatch:
    """Result of a correlation pattern match.

    Attributes:
        pattern_name: Name of the matched pattern.
        description: Human-readable description.
        involved_event_uids: UIDs of events that form this pattern.
    """

    __slots__ = ("pattern_name", "description", "involved_event_uids")

    def __init__(
        self,
        pattern_name: str,
        description: str,
        involved_event_uids: list[str],
    ) -> None:
        self.pattern_name = pattern_name
        self.description = description
        self.involved_event_uids = involved_event_uids
