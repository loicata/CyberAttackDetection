"""Tests for the SQLite database manager."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.core.database import Database
from src.core.enums import (
    AlertSeverity,
    AlertStatus,
    AlertType,
    EvidenceType,
    ResponseType,
)
from src.core.exceptions import DatabaseError
from src.core.models import Alert, Evidence, RawEvent, ResponseRecord


class TestDatabaseInit:
    """Tests for database initialization."""

    def test_initialize_creates_file(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        db = Database(db_path=str(db_path))
        db.initialize()
        assert db_path.exists()

    def test_initialize_creates_parent_dirs(self, tmp_path: Path) -> None:
        db_path = tmp_path / "sub" / "dir" / "test.db"
        db = Database(db_path=str(db_path))
        db.initialize()
        assert db_path.exists()

    def test_double_initialize_is_safe(self, tmp_database: Database) -> None:
        tmp_database.initialize()  # Should not raise

    def test_empty_path_raises(self) -> None:
        with pytest.raises(DatabaseError, match="must not be empty"):
            Database(db_path="")

    def test_operations_before_init_raise(self, tmp_path: Path) -> None:
        db = Database(db_path=str(tmp_path / "uninit.db"))
        with pytest.raises(DatabaseError, match="not initialized"):
            db.get_alerts()


class TestAlertCRUD:
    """Tests for alert insert and query operations."""

    def test_insert_and_retrieve(self, tmp_database: Database, sample_alert: Alert) -> None:
        tmp_database.insert_alert(sample_alert)
        alerts = tmp_database.get_alerts()
        assert len(alerts) == 1
        assert alerts[0]["alert_uid"] == sample_alert.alert_uid
        assert alerts[0]["severity"] == "HIGH"
        assert alerts[0]["score"] == 65

    def test_duplicate_insert_raises(
        self, tmp_database: Database, sample_alert: Alert
    ) -> None:
        tmp_database.insert_alert(sample_alert)
        with pytest.raises(DatabaseError, match="already exists"):
            tmp_database.insert_alert(sample_alert)

    def test_filter_by_status(self, tmp_database: Database, sample_raw_event: RawEvent) -> None:
        alert1 = Alert(
            alert_type=AlertType.NETWORK,
            severity=AlertSeverity.HIGH,
            score=65,
            title="Alert 1",
            description="Desc",
            raw_event=sample_raw_event,
            status=AlertStatus.NEW,
        )
        alert2 = Alert(
            alert_type=AlertType.PROCESS,
            severity=AlertSeverity.LOW,
            score=25,
            title="Alert 2",
            description="Desc",
            raw_event=sample_raw_event,
            status=AlertStatus.RESOLVED,
        )
        tmp_database.insert_alert(alert1)
        tmp_database.insert_alert(alert2)

        new_alerts = tmp_database.get_alerts(status=AlertStatus.NEW)
        assert len(new_alerts) == 1
        assert new_alerts[0]["title"] == "Alert 1"

    def test_update_status(self, tmp_database: Database, sample_alert: Alert) -> None:
        tmp_database.insert_alert(sample_alert)
        tmp_database.update_alert_status(
            sample_alert.alert_uid, AlertStatus.INVESTIGATING, "2026-01-01T00:00:00Z"
        )
        alerts = tmp_database.get_alerts()
        assert alerts[0]["status"] == "investigating"

    def test_update_nonexistent_alert_raises(self, tmp_database: Database) -> None:
        with pytest.raises(DatabaseError, match="not found"):
            tmp_database.update_alert_status(
                "nonexistent-uid", AlertStatus.RESOLVED, "2026-01-01T00:00:00Z"
            )


class TestEvidenceCRUD:
    """Tests for evidence insert and query operations."""

    def test_insert_and_retrieve(
        self, tmp_database: Database, sample_alert: Alert
    ) -> None:
        tmp_database.insert_alert(sample_alert)
        evidence = Evidence(
            alert_uid=sample_alert.alert_uid,
            evidence_type=EvidenceType.PROCESS_LIST,
            file_path="/tmp/procs.json",
            sha256_hash="abc123def456",
        )
        tmp_database.insert_evidence(evidence)
        records = tmp_database.get_evidence_for_alert(sample_alert.alert_uid)
        assert len(records) == 1
        assert records[0]["sha256_hash"] == "abc123def456"


class TestResponseCRUD:
    """Tests for response log operations."""

    def test_insert_response(
        self, tmp_database: Database, sample_alert: Alert
    ) -> None:
        tmp_database.insert_alert(sample_alert)
        record = ResponseRecord(
            alert_uid=sample_alert.alert_uid,
            action_type=ResponseType.BLOCK_IP,
            parameters={"ip": "1.2.3.4"},
        )
        tmp_database.insert_response(record)
        # No assertion needed beyond no exception


class TestBaselineCRUD:
    """Tests for baseline upsert and query."""

    def test_upsert_new_baseline(self, tmp_database: Database) -> None:
        tmp_database.upsert_baseline(
            "process", "svchost.exe", '{"avg_cpu": 0.5}', "2026-01-01T00:00:00Z"
        )
        result = tmp_database.get_baseline("process", "svchost.exe")
        assert result is not None
        assert result["sample_count"] == 1

    def test_upsert_increments_count(self, tmp_database: Database) -> None:
        ts = "2026-01-01T00:00:00Z"
        tmp_database.upsert_baseline("process", "svchost.exe", '{"avg_cpu": 0.5}', ts)
        tmp_database.upsert_baseline("process", "svchost.exe", '{"avg_cpu": 0.6}', ts)
        result = tmp_database.get_baseline("process", "svchost.exe")
        assert result is not None
        assert result["sample_count"] == 2

    def test_get_nonexistent_baseline(self, tmp_database: Database) -> None:
        result = tmp_database.get_baseline("process", "nonexistent.exe")
        assert result is None


class TestWhitelistCRUD:
    """Tests for whitelist operations."""

    def test_upsert_and_retrieve(self, tmp_database: Database) -> None:
        tmp_database.upsert_whitelist(
            "process", "svchost.exe", "Windows system process",
            "system", "2026-01-01T00:00:00Z",
        )
        entries = tmp_database.get_whitelist("process")
        assert len(entries) == 1
        assert entries[0]["value"] == "svchost.exe"

    def test_upsert_updates_reason(self, tmp_database: Database) -> None:
        ts = "2026-01-01T00:00:00Z"
        tmp_database.upsert_whitelist("ip", "1.2.3.4", "First reason", "system", ts)
        tmp_database.upsert_whitelist("ip", "1.2.3.4", "Updated reason", "user", ts)
        entries = tmp_database.get_whitelist("ip")
        assert len(entries) == 1
        assert entries[0]["reason"] == "Updated reason"

    def test_get_all_whitelist(self, tmp_database: Database) -> None:
        ts = "2026-01-01T00:00:00Z"
        tmp_database.upsert_whitelist("process", "a.exe", "r", "s", ts)
        tmp_database.upsert_whitelist("ip", "1.2.3.4", "r", "s", ts)
        entries = tmp_database.get_whitelist()
        assert len(entries) == 2
