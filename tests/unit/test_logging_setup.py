"""Tests for logging configuration."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from src.core.logging_setup import setup_logging, LOG_FORMAT, LOG_DATE_FORMAT


class TestSetupLogging:
    """Tests for setup_logging."""

    def test_setup_info_level(self) -> None:
        setup_logging(level="INFO")
        root = logging.getLogger()
        assert root.level == logging.INFO

    def test_setup_debug_level(self) -> None:
        setup_logging(level="DEBUG")
        root = logging.getLogger()
        assert root.level == logging.DEBUG

    def test_setup_warning_level(self) -> None:
        setup_logging(level="WARNING")
        root = logging.getLogger()
        assert root.level == logging.WARNING

    def test_invalid_level_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid log level"):
            setup_logging(level="NONEXISTENT")

    def test_case_insensitive(self) -> None:
        setup_logging(level="info")
        root = logging.getLogger()
        assert root.level == logging.INFO

    def test_creates_console_handler(self) -> None:
        setup_logging(level="INFO")
        root = logging.getLogger()
        has_stream_handler = any(
            isinstance(h, logging.StreamHandler) for h in root.handlers
        )
        assert has_stream_handler

    def test_creates_file_handler(self, tmp_path: Path) -> None:
        log_dir = str(tmp_path / "logs")
        setup_logging(level="INFO", log_dir=log_dir)
        root = logging.getLogger()
        has_file_handler = any(
            isinstance(h, logging.FileHandler) for h in root.handlers
        )
        assert has_file_handler
        assert (tmp_path / "logs" / "cad.log").exists()

    def test_no_file_handler_without_log_dir(self) -> None:
        setup_logging(level="INFO")
        root = logging.getLogger()
        file_handlers = [
            h for h in root.handlers if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) == 0

    def test_removes_existing_handlers_on_reinit(self) -> None:
        setup_logging(level="INFO")
        count_1 = len(logging.getLogger().handlers)
        setup_logging(level="DEBUG")
        count_2 = len(logging.getLogger().handlers)
        # Should not accumulate handlers
        assert count_2 <= count_1 + 1

    def test_suppresses_urllib3(self) -> None:
        setup_logging(level="DEBUG")
        assert logging.getLogger("urllib3").level == logging.WARNING

    def test_suppresses_watchdog(self) -> None:
        setup_logging(level="DEBUG")
        assert logging.getLogger("watchdog").level == logging.WARNING

    def test_log_format_constant(self) -> None:
        assert "%(asctime)s" in LOG_FORMAT
        assert "%(levelname)" in LOG_FORMAT
        assert "%(name)s" in LOG_FORMAT

    def test_log_date_format_constant(self) -> None:
        assert "%Y-%m-%d" in LOG_DATE_FORMAT
