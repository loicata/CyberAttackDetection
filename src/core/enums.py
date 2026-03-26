"""Enumerations for alert types, severities, and response actions."""

from enum import Enum, unique


@unique
class AlertSeverity(str, Enum):
    """Severity levels for alerts, ordered from lowest to highest."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_score(cls, score: int) -> "AlertSeverity":
        """Derive severity from a numeric score (0-100).

        Args:
            score: Alert score between 0 and 100 inclusive.

        Returns:
            The corresponding AlertSeverity.

        Raises:
            ValueError: If score is outside 0-100.
        """
        if not isinstance(score, int) or not (0 <= score <= 100):
            raise ValueError(f"Score must be an integer between 0 and 100, got {score!r}")
        if score >= 80:
            return cls.CRITICAL
        if score >= 60:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        if score >= 20:
            return cls.LOW
        return cls.INFO


@unique
class AlertType(str, Enum):
    """Source category of a detected event."""

    PROCESS = "PROCESS"
    NETWORK = "NETWORK"
    FILESYSTEM = "FILESYSTEM"
    EVENTLOG = "EVENTLOG"
    SURICATA = "SURICATA"


@unique
class AlertStatus(str, Enum):
    """Lifecycle status of an alert."""

    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@unique
class ResponseType(str, Enum):
    """Types of response actions available."""

    BLOCK_IP = "block_ip"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    ISOLATE_NETWORK = "isolate_network"
    REPORT_ONLY = "report_only"


@unique
class ResponseStatus(str, Enum):
    """Execution status of a response action."""

    PENDING = "pending"
    EXECUTED = "executed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


@unique
class DetectorState(str, Enum):
    """Operational state of a detector module."""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    ERROR = "error"
    STOPPING = "stopping"


@unique
class EvidenceType(str, Enum):
    """Categories of forensic evidence."""

    SYSTEM_SNAPSHOT = "system_snapshot"
    PROCESS_LIST = "process_list"
    NETWORK_CONNECTIONS = "network_connections"
    LOADED_DLLS = "loaded_dlls"
    SERVICES_LIST = "services_list"
    REGISTRY_PERSISTENCE = "registry_persistence"
    FILE_HASH = "file_hash"
    TIMELINE = "timeline"
    INTEL_REPORT = "intel_report"
