"""Tests for core enumerations."""

import pytest

from src.core.enums import AlertSeverity, AlertType, AlertStatus, ResponseType, DetectorState


class TestAlertSeverity:
    """Tests for AlertSeverity.from_score()."""

    def test_critical_at_80(self) -> None:
        assert AlertSeverity.from_score(80) == AlertSeverity.CRITICAL

    def test_critical_at_100(self) -> None:
        assert AlertSeverity.from_score(100) == AlertSeverity.CRITICAL

    def test_high_at_60(self) -> None:
        assert AlertSeverity.from_score(60) == AlertSeverity.HIGH

    def test_high_at_79(self) -> None:
        assert AlertSeverity.from_score(79) == AlertSeverity.HIGH

    def test_medium_at_40(self) -> None:
        assert AlertSeverity.from_score(40) == AlertSeverity.MEDIUM

    def test_medium_at_59(self) -> None:
        assert AlertSeverity.from_score(59) == AlertSeverity.MEDIUM

    def test_low_at_20(self) -> None:
        assert AlertSeverity.from_score(20) == AlertSeverity.LOW

    def test_low_at_39(self) -> None:
        assert AlertSeverity.from_score(39) == AlertSeverity.LOW

    def test_info_at_0(self) -> None:
        assert AlertSeverity.from_score(0) == AlertSeverity.INFO

    def test_info_at_19(self) -> None:
        assert AlertSeverity.from_score(19) == AlertSeverity.INFO

    def test_rejects_negative(self) -> None:
        with pytest.raises(ValueError, match="between 0 and 100"):
            AlertSeverity.from_score(-1)

    def test_rejects_over_100(self) -> None:
        with pytest.raises(ValueError, match="between 0 and 100"):
            AlertSeverity.from_score(101)

    def test_rejects_non_integer(self) -> None:
        with pytest.raises(ValueError, match="between 0 and 100"):
            AlertSeverity.from_score(50.5)  # type: ignore[arg-type]

    def test_rejects_string(self) -> None:
        with pytest.raises(ValueError, match="between 0 and 100"):
            AlertSeverity.from_score("high")  # type: ignore[arg-type]


class TestAlertType:
    """Tests for AlertType enumeration values."""

    def test_all_types_present(self) -> None:
        expected = {"PROCESS", "NETWORK", "FILESYSTEM", "EVENTLOG", "SURICATA"}
        actual = {t.value for t in AlertType}
        assert actual == expected

    def test_string_value(self) -> None:
        assert AlertType.PROCESS.value == "PROCESS"
        assert isinstance(AlertType.PROCESS, str)


class TestAlertStatus:
    """Tests for AlertStatus enumeration values."""

    def test_all_statuses_present(self) -> None:
        expected = {"new", "investigating", "resolved", "false_positive"}
        actual = {s.value for s in AlertStatus}
        assert actual == expected


class TestResponseType:
    """Tests for ResponseType enumeration values."""

    def test_all_response_types(self) -> None:
        expected = {"block_ip", "kill_process", "quarantine_file",
                    "isolate_network", "report_only"}
        actual = {r.value for r in ResponseType}
        assert actual == expected


class TestDetectorState:
    """Tests for DetectorState enumeration values."""

    def test_all_states(self) -> None:
        expected = {"stopped", "starting", "running", "error", "stopping"}
        actual = {s.value for s in DetectorState}
        assert actual == expected
