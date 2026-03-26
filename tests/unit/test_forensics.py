"""Tests for forensic modules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.config import AppConfig
from src.core.database import Database
from src.core.enums import AlertSeverity, AlertType, EvidenceType
from src.core.exceptions import EvidenceIntegrityError, ForensicError
from src.core.models import Alert, RawEvent
from src.forensics.file_hasher import compute_sha256, compute_sha256_bytes
from src.forensics.evidence_store import EvidenceStore
from src.forensics.timeline import build_timeline
from src.forensics.report_generator import generate_report


class TestFileHasher:
    """Tests for SHA-256 file hashing."""

    def test_hash_existing_file(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")
        result = compute_sha256(test_file)
        assert isinstance(result, str)
        assert len(result) == 64  # SHA-256 hex digest is 64 chars

    def test_hash_deterministic(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("deterministic")
        hash1 = compute_sha256(test_file)
        hash2 = compute_sha256(test_file)
        assert hash1 == hash2

    def test_hash_different_content(self, tmp_path: Path) -> None:
        file_a = tmp_path / "a.txt"
        file_b = tmp_path / "b.txt"
        file_a.write_text("content_a")
        file_b.write_text("content_b")
        assert compute_sha256(file_a) != compute_sha256(file_b)

    def test_hash_nonexistent_file(self) -> None:
        with pytest.raises(ForensicError, match="not found"):
            compute_sha256("/nonexistent/file.txt")

    def test_hash_empty_path_raises(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            compute_sha256("")

    def test_hash_bytes(self) -> None:
        result = compute_sha256_bytes(b"hello")
        assert isinstance(result, str)
        assert len(result) == 64

    def test_hash_bytes_non_bytes_raises(self) -> None:
        with pytest.raises(TypeError, match="Expected bytes"):
            compute_sha256_bytes("not bytes")  # type: ignore[arg-type]


class TestEvidenceStore:
    """Tests for EvidenceStore."""

    @pytest.fixture
    def evidence_store(
        self, test_config: AppConfig, tmp_database: Database
    ) -> EvidenceStore:
        return EvidenceStore(config=test_config, database=tmp_database)

    def test_store_evidence(
        self,
        evidence_store: EvidenceStore,
        tmp_database: Database,
        sample_alert: Alert,
    ) -> None:
        tmp_database.insert_alert(sample_alert)
        evidence = evidence_store.store_evidence(
            alert_uid=sample_alert.alert_uid,
            evidence_type=EvidenceType.PROCESS_LIST,
            data=[{"pid": 1, "name": "test.exe"}],
            filename="process_list.json",
        )
        assert evidence.sha256_hash
        assert Path(evidence.file_path).exists()

    def test_manifest_generation(
        self,
        evidence_store: EvidenceStore,
        tmp_database: Database,
        sample_alert: Alert,
    ) -> None:
        tmp_database.insert_alert(sample_alert)
        evidence_store.store_evidence(
            alert_uid=sample_alert.alert_uid,
            evidence_type=EvidenceType.PROCESS_LIST,
            data={"test": True},
            filename="test.json",
        )
        manifest_hash = evidence_store.generate_manifest(sample_alert.alert_uid)
        assert isinstance(manifest_hash, str)
        assert len(manifest_hash) == 64

    def test_verify_integrity_passes(
        self,
        evidence_store: EvidenceStore,
        tmp_database: Database,
        sample_alert: Alert,
    ) -> None:
        tmp_database.insert_alert(sample_alert)
        evidence_store.store_evidence(
            alert_uid=sample_alert.alert_uid,
            evidence_type=EvidenceType.PROCESS_LIST,
            data={"test": True},
            filename="test.json",
        )
        assert evidence_store.verify_integrity(sample_alert.alert_uid) is True

    def test_verify_integrity_detects_tampering(
        self,
        evidence_store: EvidenceStore,
        tmp_database: Database,
        sample_alert: Alert,
    ) -> None:
        tmp_database.insert_alert(sample_alert)
        evidence = evidence_store.store_evidence(
            alert_uid=sample_alert.alert_uid,
            evidence_type=EvidenceType.PROCESS_LIST,
            data={"original": True},
            filename="tamper_test.json",
        )
        # Tamper with the file
        Path(evidence.file_path).write_text("TAMPERED")

        with pytest.raises(EvidenceIntegrityError, match="Hash mismatch"):
            evidence_store.verify_integrity(sample_alert.alert_uid)

    def test_empty_alert_uid_raises(self, evidence_store: EvidenceStore) -> None:
        with pytest.raises(ValueError, match="alert_uid"):
            evidence_store.store_evidence(
                alert_uid="",
                evidence_type=EvidenceType.PROCESS_LIST,
                data={},
                filename="test.json",
            )


class TestTimeline:
    """Tests for timeline reconstruction."""

    def test_build_timeline_single_event(self, sample_alert: Alert) -> None:
        timeline = build_timeline(sample_alert, [])
        assert len(timeline) == 1
        assert timeline[0]["is_primary"] is True
        assert timeline[0]["sequence_number"] == 1

    def test_build_timeline_with_correlated(self, sample_alert: Alert) -> None:
        correlated = RawEvent(
            event_type=AlertType.PROCESS,
            data={"rule": "known_malware_name"},
            process_name="malware.exe",
            process_pid=999,
        )
        timeline = build_timeline(sample_alert, [correlated])
        assert len(timeline) == 2

        primary_entries = [e for e in timeline if e["is_primary"]]
        assert len(primary_entries) == 1

    def test_timeline_sorted_by_timestamp(self, sample_alert: Alert) -> None:
        events = [
            RawEvent(event_type=AlertType.PROCESS, data={"rule": "r1"}),
            RawEvent(event_type=AlertType.NETWORK, data={"rule": "r2"}),
        ]
        timeline = build_timeline(sample_alert, events)
        timestamps = [e["timestamp"] for e in timeline]
        assert timestamps == sorted(timestamps)


class TestReportGenerator:
    """Tests for report generation."""

    def test_generate_report_creates_files(
        self, sample_alert: Alert, test_config: AppConfig
    ) -> None:
        html_path, json_path = generate_report(
            alert=sample_alert,
            config=test_config,
        )
        assert html_path.exists()
        assert json_path.exists()
        assert html_path.suffix == ".html"
        assert json_path.suffix == ".json"

    def test_json_report_parseable(
        self, sample_alert: Alert, test_config: AppConfig
    ) -> None:
        _, json_path = generate_report(
            alert=sample_alert,
            config=test_config,
        )
        data = json.loads(json_path.read_text())
        assert data["alert_uid"] == sample_alert.alert_uid
        assert data["severity"] == "HIGH"
        assert data["score"] == 65

    def test_html_report_contains_alert_info(
        self, sample_alert: Alert, test_config: AppConfig
    ) -> None:
        html_path, _ = generate_report(
            alert=sample_alert,
            config=test_config,
        )
        html = html_path.read_text()
        assert "Incident Report" in html
        assert sample_alert.title in html

    def test_report_with_timeline(
        self, sample_alert: Alert, test_config: AppConfig
    ) -> None:
        timeline = [
            {
                "sequence_number": 1,
                "timestamp": "2026-01-01T00:00:00Z",
                "description": "Test event",
                "is_primary": True,
            }
        ]
        html_path, json_path = generate_report(
            alert=sample_alert,
            config=test_config,
            timeline=timeline,
        )
        assert html_path.exists()
        data = json.loads(json_path.read_text())
        assert len(data["timeline"]) == 1
