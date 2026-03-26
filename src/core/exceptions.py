"""Custom exception hierarchy for Cyber Attack Detection."""


class CADError(Exception):
    """Base exception for all Cyber Attack Detection errors."""


class ConfigError(CADError):
    """Raised when configuration is invalid or missing."""


class DatabaseError(CADError):
    """Raised when a database operation fails."""


class DetectorError(CADError):
    """Raised when a detector encounters an operational error."""


class AnalysisError(CADError):
    """Raised when the analysis pipeline encounters an error."""


class IntelError(CADError):
    """Raised when a threat intelligence lookup fails."""


class ForensicError(CADError):
    """Raised when forensic evidence collection fails."""


class ResponseError(CADError):
    """Raised when a response action fails to execute."""


class RollbackError(ResponseError):
    """Raised when a rollback operation fails."""


class EvidenceIntegrityError(ForensicError):
    """Raised when evidence integrity verification fails."""
