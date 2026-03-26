"""Extended tests for WhitelistManager to reach 80%+ coverage."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from src.core.config import AppConfig, AnalysisConfig
from src.core.database import Database
from src.core.enums import AlertType
from src.core.models import RawEvent
from src.analysis.whitelist import WhitelistManager


class TestWhitelistLoadFromDB:
    """Test _load_from_database paths."""

    def test_loads_ip_entries_from_db(
        self, tmp_database: Database, test_config: AppConfig
    ) -> None:
        tmp_database.upsert_whitelist("ip", "8.8.8.8", "DNS", "system", "2026-01-01T00:00:00Z")
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        event = RawEvent(event_type=AlertType.NETWORK, data={}, source_ip="8.8.8.8")
        assert wl.is_whitelisted(event) is True

    def test_loads_hash_entries_from_db(
        self, tmp_database: Database, test_config: AppConfig
    ) -> None:
        tmp_database.upsert_whitelist("hash", "abc123", "Known safe", "system", "2026-01-01T00:00:00Z")
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        assert "abc123" in wl._hash_cache

    def test_loads_path_entries_from_db(
        self, tmp_database: Database, test_config: AppConfig
    ) -> None:
        tmp_database.upsert_whitelist("path", r"c:\safe\app.exe", "Approved", "system", "2026-01-01T00:00:00Z")
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        event = RawEvent(event_type=AlertType.FILESYSTEM, data={}, file_path=r"C:\safe\app.exe")
        assert wl.is_whitelisted(event) is True

    def test_loads_process_entries_from_db(
        self, tmp_database: Database, test_config: AppConfig
    ) -> None:
        tmp_database.upsert_whitelist("process", "myapp.exe", "Custom", "user", "2026-01-01T00:00:00Z")
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        event = RawEvent(event_type=AlertType.PROCESS, data={}, process_name="myapp.exe")
        assert wl.is_whitelisted(event) is True


class TestWhitelistInvalidConfig:
    """Test edge cases in config loading."""

    def test_invalid_ip_range_skipped(
        self, tmp_database: Database, test_config: AppConfig
    ) -> None:
        bad_analysis = replace(
            test_config.analysis,
            whitelist_defaults={"trusted_ip_ranges": ["not_a_range"], "trusted_processes": []},
        )
        cfg = replace(test_config, analysis=bad_analysis)
        wl = WhitelistManager(database=tmp_database, config=cfg)
        wl.initialize()  # Should not raise

    def test_invalid_ip_string_not_whitelisted(
        self, tmp_database: Database, test_config: AppConfig
    ) -> None:
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        event = RawEvent(event_type=AlertType.NETWORK, data={}, source_ip="not_an_ip")
        assert wl.is_whitelisted(event) is False


class TestWhitelistProcessMatching:
    """Test process name matching edge cases."""

    def test_process_without_extension_matches(
        self, tmp_database: Database, test_config: AppConfig
    ) -> None:
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        wl.add_entry("process", "myservice", "Test", "user")
        event = RawEvent(event_type=AlertType.PROCESS, data={}, process_name="myservice.exe")
        assert wl.is_whitelisted(event) is True

    def test_case_insensitive_matching(
        self, tmp_database: Database, test_config: AppConfig
    ) -> None:
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        event = RawEvent(event_type=AlertType.PROCESS, data={}, process_name="SVCHOST.EXE")
        assert wl.is_whitelisted(event) is True


class TestWhitelistAddEntry:
    """Test add_entry for all types."""

    def test_add_hash_entry(
        self, tmp_database: Database, test_config: AppConfig
    ) -> None:
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        wl.add_entry("hash", "deadbeef1234", "Known good hash")
        assert "deadbeef1234" in wl._hash_cache

    def test_add_path_entry(
        self, tmp_database: Database, test_config: AppConfig
    ) -> None:
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        wl.add_entry("path", r"C:\MyApp\safe.dll", "Verified DLL")
        assert r"c:\myapp\safe.dll" in wl._path_cache

    def test_add_ip_entry(
        self, tmp_database: Database, test_config: AppConfig
    ) -> None:
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        wl.add_entry("ip", "203.0.113.1", "CDN server")
        assert "203.0.113.1" in wl._ip_cache

    def test_type_validation_rejects_bad(
        self, tmp_database: Database, test_config: AppConfig
    ) -> None:
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        with pytest.raises(TypeError):
            WhitelistManager(database="not_a_db", config=test_config)  # type: ignore[arg-type]


class TestWhitelistEventNone:
    """Test events with no matching fields."""

    def test_event_with_no_fields_not_whitelisted(
        self, tmp_database: Database, test_config: AppConfig
    ) -> None:
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        event = RawEvent(event_type=AlertType.NETWORK, data={})
        assert wl.is_whitelisted(event) is False

    def test_dest_ip_whitelisted(
        self, tmp_database: Database, test_config: AppConfig
    ) -> None:
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        # 192.168.x.x is in trusted_ip_ranges
        event = RawEvent(event_type=AlertType.NETWORK, data={}, dest_ip="192.168.1.1")
        assert wl.is_whitelisted(event) is True
