"""Tests for console UI functions."""

from __future__ import annotations

from io import StringIO
from unittest.mock import patch

from src.ui.console import (
    print_banner,
    print_alert,
    print_alert_table,
    print_detector_status,
    print_response_menu,
    print_success,
    print_error,
    print_warning,
    SEVERITY_COLORS,
    STATUS_COLORS,
)


class TestConsoleUI:
    """Tests for console output functions."""

    def test_print_banner_no_error(self) -> None:
        print_banner()  # Should not raise

    def test_print_alert_no_error(self) -> None:
        alert_data = {
            "title": "Test Alert",
            "severity": "HIGH",
            "score": 75,
            "alert_type": "NETWORK",
            "source_ip": "1.2.3.4",
            "source_port": 4444,
            "dest_ip": "5.6.7.8",
            "dest_port": 80,
            "process_name": "test.exe",
            "process_pid": 1234,
            "description": "Test description",
        }
        print_alert(alert_data)  # Should not raise

    def test_print_alert_minimal(self) -> None:
        print_alert({"title": "Minimal", "severity": "INFO", "score": 5,
                     "alert_type": "PROCESS", "description": "Test"})

    def test_print_alert_table_empty(self) -> None:
        print_alert_table([])  # Should not raise

    def test_print_alert_table_with_data(self) -> None:
        alerts = [
            {"severity": "HIGH", "score": 65, "title": "Test",
             "source_ip": "1.2.3.4", "status": "new", "created_at": "2026-01-01T00:00:00Z"},
        ]
        print_alert_table(alerts)

    def test_print_detector_status(self) -> None:
        detectors = [
            {"name": "process", "state": "running", "cycle_count": 10, "error_count": 0},
            {"name": "network", "state": "error", "cycle_count": 5, "error_count": 3},
        ]
        print_detector_status(detectors)

    def test_print_response_menu(self) -> None:
        actions = [
            {"type": "block_ip", "description": "Block 1.2.3.4"},
            {"type": "report_only", "description": "Generate report"},
        ]
        print_response_menu(actions)

    def test_print_success(self) -> None:
        print_success("Operation completed")

    def test_print_error(self) -> None:
        print_error("Something failed")

    def test_print_warning(self) -> None:
        print_warning("Be careful")

    def test_severity_colors_complete(self) -> None:
        expected = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert set(SEVERITY_COLORS.keys()) == expected

    def test_status_colors_complete(self) -> None:
        expected = {"new", "investigating", "resolved", "false_positive"}
        assert set(STATUS_COLORS.keys()) == expected
