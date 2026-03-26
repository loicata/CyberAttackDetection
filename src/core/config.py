"""Configuration loader with TOML parsing, validation, and environment override."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.exceptions import ConfigError

logger = logging.getLogger(__name__)

# Sentinel for required .env values that have no default
_REQUIRED = object()

def _get_base_dir() -> Path:
    """Get the base directory, handling PyInstaller frozen mode."""
    import sys

    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent.parent


def _get_install_dir() -> Path:
    """Get the actual installation directory (where the exe lives).

    Returns:
        Path to the directory containing the executable, or project root
        when running from source.
    """
    import sys

    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent.parent


def _get_data_dir() -> Path:
    """Get the writable data directory for runtime files.

    When running as a frozen exe, uses %LOCALAPPDATA%/CyberAttackDetection
    to avoid writing into Program Files. When running from source, uses
    the project-relative ./data directory.

    Returns:
        Writable directory path for data, logs, evidence, etc.
    """
    import sys

    if getattr(sys, "frozen", False):
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if local_app_data:
            return Path(local_app_data) / "CyberAttackDetection"
        return Path.home() / "AppData" / "Local" / "CyberAttackDetection"
    return Path(__file__).resolve().parent.parent.parent / "data"


DEFAULT_CONFIG_PATH = _get_base_dir() / "config" / "default.toml"
LOCAL_CONFIG_PATH = _get_base_dir() / "config" / "local.toml"

# Also look for local.toml next to the exe (install dir)
_INSTALL_LOCAL_CONFIG = _get_install_dir() / "config" / "local.toml"


def _load_toml(path: Path) -> dict[str, Any]:
    """Load a TOML file and return its contents as a dict.

    Args:
        path: Path to the TOML file.

    Returns:
        Parsed TOML data.

    Raises:
        ConfigError: If the file cannot be read or parsed.
    """
    if not path.is_file():
        raise ConfigError(f"Configuration file not found: {path}")
    try:
        import tomllib

        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except ImportError:
        pass
    try:
        import tomli

        with open(path, "rb") as fh:
            return tomli.load(fh)
    except ImportError as exc:
        raise ConfigError(
            "Neither tomllib (Python 3.11+) nor tomli is available. "
            "Install tomli: pip install tomli"
        ) from exc
    except Exception as exc:
        raise ConfigError(f"Failed to parse TOML file {path}: {exc}") from exc


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge override into base, returning a new dict.

    Args:
        base: Base configuration dictionary.
        override: Override values to merge on top.

    Returns:
        Merged dictionary (new object, does not mutate inputs).
    """
    result = base.copy()
    for key, value in override.items():
        base_value = result.get(key)
        both_are_dicts = isinstance(base_value, dict) and isinstance(value, dict)
        if both_are_dicts:
            result[key] = _deep_merge(base_value, value)
        else:
            result[key] = value
    return result


def _get_nested(data: dict[str, Any], dotted_key: str) -> Any:
    """Retrieve a value from a nested dict using dot notation.

    Args:
        data: The configuration dictionary.
        dotted_key: Key in dot notation (e.g., "database.path").

    Returns:
        The value if found, or None if any segment is missing.
    """
    parts = dotted_key.split(".")
    current: Any = data
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _set_nested(data: dict[str, Any], dotted_key: str, value: Any) -> None:
    """Set a value in a nested dict using dot notation.

    Args:
        data: The configuration dictionary (mutated in place).
        dotted_key: Key in dot notation (e.g., "database.path").
        value: Value to set.
    """
    parts = dotted_key.split(".")
    current = data
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value


def _apply_env_overrides(config: dict[str, Any], prefix: str = "CAD_") -> dict[str, Any]:
    """Override config values with environment variables prefixed with CAD_.

    Environment variable names map to config keys by replacing _ with .
    after stripping the prefix, then lowering. Example:
    CAD_DATABASE_PATH -> database.path

    Args:
        config: Configuration dictionary to override.
        prefix: Environment variable prefix.

    Returns:
        Updated configuration dictionary.
    """
    result = config.copy()
    for env_key, env_value in os.environ.items():
        if not env_key.startswith(prefix):
            continue
        config_key = env_key[len(prefix) :].lower().replace("__", ".")
        if not config_key:
            continue
        _set_nested(result, config_key, env_value)
        logger.debug("Config override from env: %s -> %s", env_key, config_key)
    return result


@dataclass(frozen=True)
class SuricataConfig:
    """Suricata detector configuration."""

    enabled: bool = False
    eve_json_path: str = ""
    syslog_listen_port: int = 0
    syslog_listen_host: str = "127.0.0.1"


@dataclass(frozen=True)
class AnalysisConfig:
    """Analysis pipeline configuration."""

    score_threshold: int = 40
    correlation_window_seconds: int = 60
    aggregation_window_seconds: int = 300
    baseline_learning_hours: int = 24
    scoring_weights: dict[str, int] = field(default_factory=dict)
    whitelist_defaults: dict[str, list[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class IntelConfig:
    """Threat intelligence configuration."""

    enabled: bool = True
    cache_ttl_hours: int = 24
    request_timeout_seconds: int = 10
    max_concurrent_lookups: int = 5
    abuseipdb_enabled: bool = False
    virustotal_enabled: bool = False


@dataclass(frozen=True)
class ForensicsConfig:
    """Forensic collection configuration."""

    evidence_dir: str = "./data/evidence"
    quarantine_dir: str = "./data/quarantine"
    report_dir: str = "./data/reports"
    snapshot_on_severity: str = "MEDIUM"
    max_evidence_age_days: int = 90


@dataclass(frozen=True)
class ResponseConfig:
    """Response framework configuration."""

    require_confirmation: bool = True
    dry_run: bool = False
    firewall_rule_prefix: str = "CAD_BLOCK_"


@dataclass(frozen=True)
class AppConfig:
    """Top-level application configuration.

    Attributes:
        app_name: Application display name.
        data_dir: Base directory for runtime data.
        log_level: Logging level string.
        db_path: Path to SQLite database.
        db_wal_mode: Whether to enable WAL mode.
        db_busy_timeout_ms: SQLite busy timeout.
        enabled_detectors: List of enabled detector names.
        polling_interval_seconds: Detector polling interval.
        eventlog_channels: Windows Event Log channels to monitor.
        sysmon_enabled: Whether Sysmon events are expected.
        event_ids_of_interest: Windows Event IDs to watch for.
        suspicious_ports: Network ports considered suspicious.
        suspicious_process_names: Process names considered malicious.
        suspicious_parent_child: Parent-child process pairs to flag.
        watched_paths: Filesystem paths to monitor.
        suspicious_extensions: File extensions to flag.
        suricata: Suricata sub-configuration.
        analysis: Analysis sub-configuration.
        intel: Intel sub-configuration.
        forensics: Forensics sub-configuration.
        response: Response sub-configuration.
        raw: Full raw config dict for extensibility.
    """

    app_name: str = "Cyber Attack Detection"
    data_dir: str = "./data"
    log_level: str = "INFO"
    db_path: str = "./data/alerts.db"
    db_wal_mode: bool = True
    db_busy_timeout_ms: int = 5000
    enabled_detectors: tuple[str, ...] = ("eventlog", "network", "process", "filesystem")
    polling_interval_seconds: int = 5
    eventlog_channels: tuple[str, ...] = ("Security", "System", "Application")
    sysmon_enabled: bool = False
    event_ids_of_interest: tuple[int, ...] = ()
    suspicious_ports: tuple[int, ...] = ()
    suspicious_process_names: tuple[str, ...] = ()
    suspicious_parent_child: tuple[tuple[str, str], ...] = ()
    watched_paths: tuple[str, ...] = ()
    suspicious_extensions: tuple[str, ...] = ()
    suricata: SuricataConfig = field(default_factory=SuricataConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    intel: IntelConfig = field(default_factory=IntelConfig)
    forensics: ForensicsConfig = field(default_factory=ForensicsConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    raw: dict[str, Any] = field(default_factory=dict)


def _resolve_data_path(raw_path: str) -> str:
    """Resolve a data path, replacing ./data with the writable data dir.

    When frozen, paths like ./data/evidence become
    %LOCALAPPDATA%/CyberAttackDetection/evidence.

    Args:
        raw_path: Raw path string from config (may start with ./data).

    Returns:
        Resolved absolute path string.
    """
    import sys

    if not getattr(sys, "frozen", False):
        return raw_path

    data_dir = _get_data_dir()

    # Normalize: strip leading ./ or .\ then check if starts with "data"
    normalized = raw_path.replace("\\", "/").lstrip("./")

    if normalized == "data" or raw_path in ("./data", ".\\data", "data"):
        return str(data_dir)

    # Match "./data/something" or "data/something"
    if normalized.startswith("data/"):
        remainder = normalized[5:]  # strip "data/"
        if remainder:
            return str(data_dir / remainder)
        return str(data_dir)

    return raw_path


def _build_app_config(data: dict[str, Any]) -> AppConfig:
    """Build an AppConfig from a raw config dictionary.

    Args:
        data: Merged configuration dictionary.

    Returns:
        Validated AppConfig instance.

    Raises:
        ConfigError: If required values are missing or invalid.
    """
    general = data.get("general", {})
    database = data.get("database", {})
    detection = data.get("detection", {})
    det_eventlog = detection.get("eventlog", {})
    det_network = detection.get("network", {})
    det_process = detection.get("process", {})
    det_filesystem = detection.get("filesystem", {})
    det_suricata = detection.get("suricata", {})
    analysis_raw = data.get("analysis", {})
    intel_raw = data.get("intel", {})
    forensics_raw = data.get("forensics", {})
    response_raw = data.get("response", {})

    score_threshold = analysis_raw.get("score_threshold", 40)
    if not isinstance(score_threshold, int) or not (0 <= score_threshold <= 100):
        raise ConfigError(f"analysis.score_threshold must be 0-100, got {score_threshold!r}")

    parent_child_raw = det_process.get("suspicious_parent_child", [])
    parent_child_tuples: list[tuple[str, str]] = []
    for pair in parent_child_raw:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ConfigError(f"Invalid parent-child pair: {pair!r}")
        parent_child_tuples.append((str(pair[0]), str(pair[1])))

    suricata_cfg = SuricataConfig(
        enabled=det_suricata.get("enabled", False),
        eve_json_path=det_suricata.get("eve_json_path", ""),
        syslog_listen_port=det_suricata.get("syslog_listen_port", 0),
        syslog_listen_host=det_suricata.get("syslog_listen_host", "127.0.0.1"),
    )

    analysis_cfg = AnalysisConfig(
        score_threshold=score_threshold,
        correlation_window_seconds=analysis_raw.get("correlation_window_seconds", 60),
        aggregation_window_seconds=analysis_raw.get("aggregation_window_seconds", 300),
        baseline_learning_hours=analysis_raw.get("baseline_learning_hours", 24),
        scoring_weights=analysis_raw.get("scoring_weights", {}),
        whitelist_defaults=analysis_raw.get("whitelist_defaults", {}),
    )

    intel_cfg = IntelConfig(
        enabled=intel_raw.get("enabled", True),
        cache_ttl_hours=intel_raw.get("cache_ttl_hours", 24),
        request_timeout_seconds=intel_raw.get("request_timeout_seconds", 10),
        max_concurrent_lookups=intel_raw.get("max_concurrent_lookups", 5),
        abuseipdb_enabled=intel_raw.get("abuseipdb", {}).get("enabled", False),
        virustotal_enabled=intel_raw.get("virustotal", {}).get("enabled", False),
    )

    forensics_cfg = ForensicsConfig(
        evidence_dir=_resolve_data_path(
            forensics_raw.get("evidence_dir", "./data/evidence")
        ),
        quarantine_dir=_resolve_data_path(
            forensics_raw.get("quarantine_dir", "./data/quarantine")
        ),
        report_dir=_resolve_data_path(
            forensics_raw.get("report_dir", "./data/reports")
        ),
        snapshot_on_severity=forensics_raw.get("snapshot_on_severity", "MEDIUM"),
        max_evidence_age_days=forensics_raw.get("max_evidence_age_days", 90),
    )

    response_cfg = ResponseConfig(
        require_confirmation=response_raw.get("require_confirmation", True),
        dry_run=response_raw.get("dry_run", False),
        firewall_rule_prefix=response_raw.get("firewall_rule_prefix", "CAD_BLOCK_"),
    )

    return AppConfig(
        app_name=general.get("app_name", "Cyber Attack Detection"),
        data_dir=_resolve_data_path(general.get("data_dir", "./data")),
        log_level=general.get("log_level", "INFO"),
        db_path=_resolve_data_path(database.get("path", "./data/alerts.db")),
        db_wal_mode=database.get("wal_mode", True),
        db_busy_timeout_ms=database.get("busy_timeout_ms", 5000),
        enabled_detectors=tuple(detection.get("enabled_detectors", [])),
        polling_interval_seconds=detection.get("polling_interval_seconds", 5),
        eventlog_channels=tuple(det_eventlog.get("channels", [])),
        sysmon_enabled=det_eventlog.get("sysmon_enabled", False),
        event_ids_of_interest=tuple(det_eventlog.get("event_ids_of_interest", [])),
        suspicious_ports=tuple(det_network.get("suspicious_ports", [])),
        suspicious_process_names=tuple(det_process.get("suspicious_process_names", [])),
        suspicious_parent_child=tuple(parent_child_tuples),
        watched_paths=tuple(det_filesystem.get("watched_paths", [])),
        suspicious_extensions=tuple(det_filesystem.get("suspicious_extensions", [])),
        suricata=suricata_cfg,
        analysis=analysis_cfg,
        intel=intel_cfg,
        forensics=forensics_cfg,
        response=response_cfg,
        raw=data,
    )


def load_config(
    default_path: Path | None = None,
    local_path: Path | None = None,
) -> AppConfig:
    """Load and merge configuration from TOML files and environment.

    Args:
        default_path: Path to default config. Uses built-in default if None.
        local_path: Path to local override config. Skipped if None or missing.

    Returns:
        Validated AppConfig instance.

    Raises:
        ConfigError: If configuration is invalid.
    """
    effective_default = default_path or DEFAULT_CONFIG_PATH
    config = _load_toml(effective_default)
    logger.info("Loaded default config from %s", effective_default)

    effective_local = local_path or LOCAL_CONFIG_PATH
    if effective_local.is_file():
        local_data = _load_toml(effective_local)
        config = _deep_merge(config, local_data)
        logger.info("Merged local config from %s", effective_local)

    # Also check for local.toml next to the installed exe (e.g. Program Files)
    if _INSTALL_LOCAL_CONFIG.is_file() and _INSTALL_LOCAL_CONFIG != effective_local:
        install_local_data = _load_toml(_INSTALL_LOCAL_CONFIG)
        config = _deep_merge(config, install_local_data)
        logger.info("Merged install-dir config from %s", _INSTALL_LOCAL_CONFIG)

    config = _apply_env_overrides(config)

    return _build_app_config(config)
