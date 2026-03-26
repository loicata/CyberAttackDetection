"""Tests for core data models."""

import json
from dataclasses import asdict

import pytest

from src.core.enums import AlertSeverity, AlertStatus, AlertType, EvidenceType, ResponseType
from src.core.models import Alert, Evidence, IntelResult, RawEvent, ResponseRecord


class TestRawEvent:
    """Tests for RawEvent dataclass."""

    def test_creation_with_required_fields(self) -> None:
        event = RawEvent(event_type=AlertType.NETWORK, data={"key": "value"})
        assert event.event_type == AlertType.NETWORK
        assert event.data == {"key": "value"}
        assert event.event_uid  # auto-generated UUID
        assert event.timestamp  # auto-generated timestamp
        assert event.source_ip is None

    def test_creation_with_all_fields(self) -> None:
        event = RawEvent(
            event_type=AlertType.PROCESS,
            data={"name": "test"},
            source_ip="1.2.3.4",
            source_port=80,
            dest_ip="5.6.7.8",
            dest_port=443,
            process_name="test.exe",
            process_pid=123,
            file_path=r"C:\test.exe",
        )
        assert event.source_ip == "1.2.3.4"
        assert event.process_pid == 123

    def test_is_immutable(self) -> None:
        event = RawEvent(event_type=AlertType.NETWORK, data={})
        with pytest.raises(AttributeError):
            event.source_ip = "1.2.3.4"  # type: ignore[misc]

    def test_unique_uids(self) -> None:
        e1 = RawEvent(event_type=AlertType.NETWORK, data={})
        e2 = RawEvent(event_type=AlertType.NETWORK, data={})
        assert e1.event_uid != e2.event_uid

    def test_serializable_to_dict(self) -> None:
        event = RawEvent(event_type=AlertType.NETWORK, data={"x": 1})
        d = asdict(event)
        assert d["event_type"] == "NETWORK"
        assert d["data"] == {"x": 1}

    def test_serializable_to_json(self) -> None:
        event = RawEvent(event_type=AlertType.NETWORK, data={"x": 1})
        result = json.dumps(asdict(event))
        assert isinstance(result, str)


class TestAlert:
    """Tests for Alert dataclass."""

    def test_creation_defaults(self, sample_raw_event: RawEvent) -> None:
        alert = Alert(
            alert_type=AlertType.NETWORK,
            severity=AlertSeverity.HIGH,
            score=65,
            title="Test",
            description="Test description",
            raw_event=sample_raw_event,
        )
        assert alert.status == AlertStatus.NEW
        assert alert.is_false_positive is False
        assert alert.occurrence_count == 1
        assert alert.correlated_event_uids == []
        assert alert.alert_uid  # auto-generated

    def test_is_mutable(self, sample_raw_event: RawEvent) -> None:
        alert = Alert(
            alert_type=AlertType.NETWORK,
            severity=AlertSeverity.LOW,
            score=25,
            title="Mutable",
            description="Test",
            raw_event=sample_raw_event,
        )
        alert.status = AlertStatus.INVESTIGATING
        assert alert.status == AlertStatus.INVESTIGATING

    def test_occurrence_count_increment(self, sample_alert: Alert) -> None:
        sample_alert.occurrence_count += 1
        assert sample_alert.occurrence_count == 2


class TestEvidence:
    """Tests for Evidence dataclass."""

    def test_creation(self) -> None:
        ev = Evidence(
            alert_uid="test-alert-uid",
            evidence_type=EvidenceType.PROCESS_LIST,
            file_path="/tmp/evidence/procs.json",
            sha256_hash="abc123",
        )
        assert ev.alert_uid == "test-alert-uid"
        assert ev.evidence_type == EvidenceType.PROCESS_LIST
        assert ev.metadata == {}

    def test_is_immutable(self) -> None:
        ev = Evidence(
            alert_uid="uid",
            evidence_type=EvidenceType.FILE_HASH,
            file_path="/x",
            sha256_hash="abc",
        )
        with pytest.raises(AttributeError):
            ev.sha256_hash = "new"  # type: ignore[misc]


class TestIntelResult:
    """Tests for IntelResult dataclass."""

    def test_creation_minimal(self) -> None:
        result = IntelResult(ip_address="8.8.8.8")
        assert result.ip_address == "8.8.8.8"
        assert result.reverse_dns == []
        assert result.abuse_score is None

    def test_creation_full(self) -> None:
        result = IntelResult(
            ip_address="1.2.3.4",
            reverse_dns=["host.example.com"],
            whois_org="Example Inc",
            geoip_country="US",
            abuse_score=75,
            abuse_reports=42,
        )
        assert result.whois_org == "Example Inc"
        assert result.abuse_score == 75


class TestResponseRecord:
    """Tests for ResponseRecord dataclass."""

    def test_creation_defaults(self) -> None:
        rec = ResponseRecord(
            alert_uid="alert-uid",
            action_type=ResponseType.BLOCK_IP,
            parameters={"ip": "1.2.3.4"},
        )
        assert rec.status.value == "pending"
        assert rec.rollback_data is None
        assert rec.executed_at is None
