"""Shared test fixtures for the Cyber Attack Detection test suite."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from src.core.config import AppConfig, AnalysisConfig, ForensicsConfig, ResponseConfig
from src.core.database import Database
from src.core.enums import AlertSeverity, AlertStatus, AlertType
from src.core.event_bus import EventBus
from src.core.models import Alert, RawEvent


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    """Provide a temporary directory for test data."""
    return tmp_path


@pytest.fixture
def test_config(tmp_path: Path) -> AppConfig:
    """Provide a test configuration with temp paths."""
    return AppConfig(
        app_name="TestCAD",
        data_dir=str(tmp_path / "data"),
        log_level="DEBUG",
        db_path=str(tmp_path / "data" / "test.db"),
        db_wal_mode=True,
        db_busy_timeout_ms=1000,
        enabled_detectors=("process", "network"),
        polling_interval_seconds=1,
        eventlog_channels=("Security", "System"),
        sysmon_enabled=False,
        event_ids_of_interest=(4624, 4625, 4688, 1102),
        suspicious_ports=(4444, 5555, 1337),
        suspicious_process_names=("mimikatz", "nc.exe"),
        suspicious_parent_child=(("winword.exe", "cmd.exe"),),
        watched_paths=(),
        suspicious_extensions=(".exe", ".dll"),
        analysis=AnalysisConfig(
            score_threshold=40,
            correlation_window_seconds=60,
            aggregation_window_seconds=300,
            baseline_learning_hours=1,
            scoring_weights={
                "known_malware_name": 90,
                "suspicious_parent_child": 70,
                "eventlog_critical_event": 65,
                "suspicious_port_connection": 55,
                "new_listening_port": 50,
                "filesystem_change_system32": 60,
                "suricata_high_severity": 80,
                "suricata_medium_severity": 50,
                "multiple_failed_logins": 60,
                "log_clearing": 85,
                "new_service_installed": 45,
            },
            whitelist_defaults={
                "trusted_processes": ["svchost.exe", "explorer.exe"],
                "trusted_ip_ranges": ["192.168.0.0/16"],
            },
        ),
        forensics=ForensicsConfig(
            evidence_dir=str(tmp_path / "evidence"),
            quarantine_dir=str(tmp_path / "quarantine"),
            report_dir=str(tmp_path / "reports"),
            snapshot_on_severity="MEDIUM",
            max_evidence_age_days=90,
        ),
        response=ResponseConfig(
            require_confirmation=False,
            dry_run=True,
            firewall_rule_prefix="TEST_BLOCK_",
        ),
    )


@pytest.fixture
def tmp_database(tmp_path: Path) -> Database:
    """Provide an initialized temporary database."""
    db = Database(db_path=str(tmp_path / "test.db"))
    db.initialize()
    return db


@pytest.fixture
def event_bus() -> EventBus:
    """Provide a fresh event bus."""
    return EventBus(max_queue_size=100)


@pytest.fixture
def sample_raw_event() -> RawEvent:
    """Provide a sample RawEvent for testing."""
    return RawEvent(
        event_type=AlertType.NETWORK,
        data={"connection": "192.168.1.100:4444 -> 10.0.0.1:80"},
        source_ip="192.168.1.100",
        source_port=4444,
        dest_ip="10.0.0.1",
        dest_port=80,
        process_name="suspicious.exe",
        process_pid=1234,
    )


@pytest.fixture
def sample_alert(sample_raw_event: RawEvent) -> Alert:
    """Provide a sample Alert for testing."""
    return Alert(
        alert_type=AlertType.NETWORK,
        severity=AlertSeverity.HIGH,
        score=65,
        title="Suspicious outbound connection",
        description="Connection to known suspicious port 4444 detected",
        raw_event=sample_raw_event,
        source_ip="192.168.1.100",
        source_port=4444,
        dest_ip="10.0.0.1",
        dest_port=80,
        process_name="suspicious.exe",
        process_pid=1234,
    )
