"""Core data models used across all modules."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.core.enums import (
    AlertSeverity,
    AlertStatus,
    AlertType,
    EvidenceType,
    ResponseStatus,
    ResponseType,
)


def _utc_now() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _new_uid() -> str:
    """Generate a new UUID4 string."""
    return str(uuid.uuid4())


@dataclass(frozen=True)
class RawEvent:
    """An unprocessed event emitted by a detector.

    Attributes:
        event_uid: Unique identifier for this event.
        event_type: Category of the event source.
        timestamp: ISO 8601 UTC timestamp of detection.
        data: Arbitrary event payload (detector-specific).
        source_ip: Source IP address if applicable.
        source_port: Source port if applicable.
        dest_ip: Destination IP address if applicable.
        dest_port: Destination port if applicable.
        process_name: Related process name if applicable.
        process_pid: Related process ID if applicable.
        file_path: Related file path if applicable.
    """

    event_type: AlertType
    data: dict[str, Any]
    event_uid: str = field(default_factory=_new_uid)
    timestamp: str = field(default_factory=_utc_now)
    source_ip: str | None = None
    source_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    process_name: str | None = None
    process_pid: int | None = None
    file_path: str | None = None


@dataclass
class Alert:
    """A confirmed or potential threat that passed the analysis pipeline.

    Attributes:
        alert_uid: Unique identifier for this alert.
        alert_type: Category of the event source.
        severity: Computed severity level.
        score: Numeric confidence score (0-100).
        title: Short human-readable title.
        description: Detailed description of the threat.
        raw_event: The original event that triggered this alert.
        status: Current lifecycle status.
        source_ip: Source IP address if applicable.
        source_port: Source port if applicable.
        dest_ip: Destination IP address if applicable.
        dest_port: Destination port if applicable.
        process_name: Related process name if applicable.
        process_pid: Related process ID if applicable.
        file_path: Related file path if applicable.
        intel_data: Enrichment data from threat intelligence.
        is_false_positive: Whether user marked as false positive.
        created_at: ISO 8601 UTC timestamp of creation.
        updated_at: ISO 8601 UTC timestamp of last update.
        resolved_at: ISO 8601 UTC timestamp of resolution.
        correlated_event_uids: UIDs of correlated events.
        occurrence_count: Number of deduplicated occurrences.
    """

    alert_type: AlertType
    severity: AlertSeverity
    score: int
    title: str
    description: str
    raw_event: RawEvent
    alert_uid: str = field(default_factory=_new_uid)
    status: AlertStatus = AlertStatus.NEW
    source_ip: str | None = None
    source_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    process_name: str | None = None
    process_pid: int | None = None
    file_path: str | None = None
    intel_data: dict[str, Any] | None = None
    is_false_positive: bool = False
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    resolved_at: str | None = None
    correlated_event_uids: list[str] = field(default_factory=list)
    occurrence_count: int = 1


@dataclass(frozen=True)
class Evidence:
    """A piece of forensic evidence linked to an alert.

    Attributes:
        evidence_uid: Unique identifier for this evidence.
        alert_uid: UID of the associated alert.
        evidence_type: Category of evidence.
        file_path: Path to the evidence file on disk.
        sha256_hash: Integrity hash of the evidence file.
        collected_at: ISO 8601 UTC timestamp of collection.
        metadata: Additional context about this evidence.
    """

    alert_uid: str
    evidence_type: EvidenceType
    file_path: str
    sha256_hash: str
    evidence_uid: str = field(default_factory=_new_uid)
    collected_at: str = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IntelResult:
    """Result of a threat intelligence lookup for an IP address.

    Attributes:
        ip_address: The IP that was looked up.
        reverse_dns: Reverse DNS hostname(s).
        whois_org: WHOIS organization name.
        whois_country: WHOIS country code.
        whois_raw: Raw WHOIS text.
        geoip_country: GeoIP country.
        geoip_city: GeoIP city.
        geoip_lat: GeoIP latitude.
        geoip_lon: GeoIP longitude.
        abuse_score: AbuseIPDB confidence score.
        abuse_reports: Number of AbuseIPDB reports.
        virustotal_malicious: VirusTotal malicious detections.
        virustotal_total: VirusTotal total engines.
        traceroute_hops: List of traceroute hops.
        collected_at: ISO 8601 UTC timestamp.
    """

    ip_address: str
    reverse_dns: list[str] = field(default_factory=list)
    whois_org: str | None = None
    whois_country: str | None = None
    whois_raw: str | None = None
    geoip_country: str | None = None
    geoip_city: str | None = None
    geoip_lat: float | None = None
    geoip_lon: float | None = None
    abuse_score: int | None = None
    abuse_reports: int | None = None
    virustotal_malicious: int | None = None
    virustotal_total: int | None = None
    traceroute_hops: list[dict[str, Any]] = field(default_factory=list)
    collected_at: str = field(default_factory=_utc_now)


@dataclass
class ResponseRecord:
    """Record of a response action taken against a threat.

    Attributes:
        response_uid: Unique identifier.
        alert_uid: UID of the associated alert.
        action_type: Type of response action.
        parameters: Action-specific parameters.
        rollback_data: Data needed to undo the action.
        status: Current execution status.
        executed_at: When the action was executed.
        rolled_back_at: When the action was rolled back.
        error_message: Error message if action failed.
    """

    alert_uid: str
    action_type: ResponseType
    parameters: dict[str, Any]
    response_uid: str = field(default_factory=_new_uid)
    rollback_data: dict[str, Any] | None = None
    status: ResponseStatus = ResponseStatus.PENDING
    executed_at: str | None = None
    rolled_back_at: str | None = None
    error_message: str | None = None
