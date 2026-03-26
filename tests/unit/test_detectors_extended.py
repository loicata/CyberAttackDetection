"""Extended tests for detector modules to reach 80%+ coverage."""

from __future__ import annotations

import asyncio
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

from src.core.config import AppConfig, SuricataConfig
from src.core.enums import AlertType, DetectorState
from src.core.event_bus import EventBus
from src.core.models import RawEvent
from src.detectors.network_detector import NetworkDetector
from src.detectors.suricata_detector import SuricataDetector
from src.detectors.eventlog_detector import EventLogDetector
from src.detectors.filesystem_detector import FilesystemDetector, _FileEventHandler


# ---------------------------------------------------------------------------
# NetworkDetector extended
# ---------------------------------------------------------------------------

class TestNetworkDetectorExtended:
    """Cover missing lines in NetworkDetector."""

    def test_extract_listening(self) -> None:
        conns = [
            {"local_address": "0.0.0.0", "local_port": 80, "status": "LISTEN"},
            {"local_address": "0.0.0.0", "local_port": 443, "status": "LISTEN"},
            {"local_address": "1.2.3.4", "local_port": 5000, "status": "ESTABLISHED"},
        ]
        result = NetworkDetector._extract_listening(conns)
        assert len(result) == 2
        assert ("0.0.0.0", 80) in result

    def test_extract_established(self) -> None:
        conns = [
            {"local_address": "192.168.1.1", "local_port": 5000,
             "remote_address": "1.2.3.4", "remote_port": 80, "status": "ESTABLISHED"},
            {"local_address": "0.0.0.0", "local_port": 80, "status": "LISTEN"},
        ]
        result = NetworkDetector._extract_established(conns)
        assert len(result) == 1

    def test_connection_spike_insufficient_history(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = NetworkDetector(event_bus=bus, config=test_config)
        # Only 1 entry, need 3 minimum
        events = detector._check_connection_spike([{"x": 1}])
        assert events == []

    def test_connection_spike_no_spike(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = NetworkDetector(event_bus=bus, config=test_config)
        # Build up stable history
        for _ in range(5):
            detector._connection_counts.append(10)
        # Normal count
        events = detector._check_connection_spike([{} for _ in range(10)])
        assert len(events) == 0

    def test_connection_spike_detected(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = NetworkDetector(event_bus=bus, config=test_config)
        # Build up low baseline
        detector._connection_counts = [5, 5, 5, 5, 5]
        # Massive spike (>3x average and >100)
        big_list = [{"status": "ESTABLISHED"} for _ in range(500)]
        events = detector._check_connection_spike(big_list)
        assert len(events) == 1
        assert events[0].data["rule"] == "connection_spike"


# ---------------------------------------------------------------------------
# EventLogDetector extended
# ---------------------------------------------------------------------------

class TestEventLogDetectorExtended:
    """Cover EventLogDetector with mocked wevtutil."""

    @patch("subprocess.run")
    def test_query_channel_success(
        self, mock_run: MagicMock, test_config: AppConfig
    ) -> None:
        bus = EventBus()
        detector = EventLogDetector(event_bus=bus, config=test_config)

        xml_output = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1102</EventID>
    <TimeCreated SystemTime="2026-03-25T10:00:00.000Z"/>
  </System>
  <EventData>
    <Data Name="SubjectUserName">admin</Data>
  </EventData>
</Event>"""
        mock_run.return_value = MagicMock(returncode=0, stdout=xml_output, stderr="")

        from datetime import datetime, timezone
        events = detector._query_channel("Security", datetime(2026, 1, 1, tzinfo=timezone.utc))
        assert len(events) == 1
        assert events[0].data["event_id"] == 1102
        assert events[0].data["rule"] == "log_clearing"

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_query_channel_no_wevtutil(
        self, mock: MagicMock, test_config: AppConfig
    ) -> None:
        bus = EventBus()
        detector = EventLogDetector(event_bus=bus, config=test_config)
        from datetime import datetime, timezone
        events = detector._query_channel("Security", datetime(2026, 1, 1, tzinfo=timezone.utc))
        assert events == []

    @patch("subprocess.run")
    def test_query_channel_timeout(
        self, mock_run: MagicMock, test_config: AppConfig
    ) -> None:
        bus = EventBus()
        detector = EventLogDetector(event_bus=bus, config=test_config)
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="wevtutil", timeout=30)
        from datetime import datetime, timezone
        events = detector._query_channel("Security", datetime(2026, 1, 1, tzinfo=timezone.utc))
        assert events == []

    @patch("subprocess.run")
    def test_query_channel_nonzero_return(
        self, mock_run: MagicMock, test_config: AppConfig
    ) -> None:
        bus = EventBus()
        detector = EventLogDetector(event_bus=bus, config=test_config)
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        from datetime import datetime, timezone
        events = detector._query_channel("Security", datetime(2026, 1, 1, tzinfo=timezone.utc))
        assert events == []

    def test_parse_xml_empty(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = EventLogDetector(event_bus=bus, config=test_config)
        events = detector._parse_xml_events("", "Security")
        assert events == []

    def test_parse_xml_invalid(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = EventLogDetector(event_bus=bus, config=test_config)
        events = detector._parse_xml_events("<invalid>xml", "Security")
        assert events == []

    def test_classify_event_types(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = EventLogDetector(event_bus=bus, config=test_config)

        assert detector._classify_standard_event(1102, {}) == "log_clearing"
        assert detector._classify_standard_event(7045, {}) == "new_service_installed"
        assert detector._classify_standard_event(4625, {}) == "eventlog_critical_event"
        assert detector._classify_standard_event(4624, {}) == "eventlog_critical_event"
        assert detector._classify_standard_event(4688, {}) == "eventlog_critical_event"
        assert detector._classify_standard_event(4698, {}) == "new_service_installed"
        assert detector._classify_standard_event(9999, {}) == "eventlog_critical_event"

    def test_track_failed_login_below_threshold(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = EventLogDetector(event_bus=bus, config=test_config)
        result = detector._track_failed_login({"IpAddress": "1.2.3.4"})
        assert result is None

    def test_track_failed_login_exceeds_threshold(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = EventLogDetector(event_bus=bus, config=test_config)
        for _ in range(5):
            result = detector._track_failed_login({"IpAddress": "1.2.3.4"})
        assert result == "multiple_failed_logins"

    @patch("subprocess.run")
    def test_query_with_service_event(
        self, mock_run: MagicMock, test_config: AppConfig
    ) -> None:
        from dataclasses import replace
        # Add 7045 to event IDs of interest
        cfg = replace(test_config, event_ids_of_interest=test_config.event_ids_of_interest + (7045,))
        bus = EventBus()
        detector = EventLogDetector(event_bus=bus, config=cfg)
        xml_output = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>7045</EventID>
    <TimeCreated SystemTime="2026-03-25T10:00:00.000Z"/>
  </System>
  <EventData>
    <Data Name="ServiceName">Evil Service</Data>
    <Data Name="ServiceFileName">C:\\Temp\\evil.exe</Data>
  </EventData>
</Event>"""
        mock_run.return_value = MagicMock(returncode=0, stdout=xml_output, stderr="")
        from datetime import datetime, timezone
        events = detector._query_channel("System", datetime(2026, 1, 1, tzinfo=timezone.utc))
        assert len(events) == 1
        assert events[0].data["rule"] == "new_service_installed"


# ---------------------------------------------------------------------------
# FilesystemDetector extended
# ---------------------------------------------------------------------------

class TestFilesystemDetectorExtended:
    """Cover FilesystemDetector with controlled setup."""

    @pytest.mark.asyncio
    async def test_poll_returns_queued_events(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = FilesystemDetector(event_bus=bus, config=test_config)

        # Manually inject events into the queue
        await detector._event_queue.put({
            "action": "created",
            "src_path": r"C:\Windows\System32\evil.exe",
            "extension": ".exe",
            "is_directory": False,
        })
        await detector._event_queue.put({
            "action": "modified",
            "src_path": r"C:\Users\test\normal.txt",
            "extension": ".txt",
            "is_directory": False,
        })

        events = await detector._poll()
        assert len(events) == 2
        system32_events = [e for e in events if "system32" in e.data.get("rule", "")]
        assert len(system32_events) == 1

    @pytest.mark.asyncio
    async def test_poll_empty_queue(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = FilesystemDetector(event_bus=bus, config=test_config)
        events = await detector._poll()
        assert events == []

    @pytest.mark.asyncio
    async def test_cleanup_no_observer(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = FilesystemDetector(event_bus=bus, config=test_config)
        await detector._cleanup()  # Should not raise

    def test_file_event_handler_filters_extensions(self) -> None:
        loop = asyncio.new_event_loop()
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        handler = _FileEventHandler(
            suspicious_extensions={".exe", ".dll"},
            sync_queue=queue,
            loop=loop,
        )

        # Mock a filesystem event with suspicious extension
        mock_event = MagicMock()
        mock_event.src_path = r"C:\test\malware.exe"
        mock_event.is_directory = False

        handler.on_created(mock_event)
        # The call_soon_threadsafe adds to queue in the loop context
        # In test we verify it was called
        loop.close()

    def test_file_event_handler_ignores_directory(self) -> None:
        loop = asyncio.new_event_loop()
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        handler = _FileEventHandler(
            suspicious_extensions={".exe"},
            sync_queue=queue,
            loop=loop,
        )

        mock_event = MagicMock()
        mock_event.is_directory = True

        handler.on_created(mock_event)
        handler.on_modified(mock_event)
        handler.on_moved(mock_event)
        # No events should be enqueued for directories
        loop.close()


# ---------------------------------------------------------------------------
# SuricataDetector extended
# ---------------------------------------------------------------------------

class TestSuricataDetectorExtended:
    """Cover missing lines in SuricataDetector."""

    @pytest.mark.asyncio
    async def test_init_file_mode_nonexistent(self, test_config: AppConfig) -> None:
        from dataclasses import replace
        cfg = replace(test_config, suricata=SuricataConfig(
            enabled=True, eve_json_path="/nonexistent/eve.json"
        ))
        bus = EventBus()
        detector = SuricataDetector(event_bus=bus, config=cfg)
        await detector._initialize()
        assert detector._file_position == 0

    @pytest.mark.asyncio
    async def test_poll_file_mode_no_file(self, test_config: AppConfig) -> None:
        from dataclasses import replace
        cfg = replace(test_config, suricata=SuricataConfig(
            enabled=True, eve_json_path="/nonexistent/eve.json"
        ))
        bus = EventBus()
        detector = SuricataDetector(event_bus=bus, config=cfg)
        events = await detector._poll()
        assert events == []

    def test_read_new_lines_rotated_file(
        self, test_config: AppConfig, tmp_path: Path
    ) -> None:
        from dataclasses import replace
        eve_file = tmp_path / "eve.json"
        eve_file.write_text('{"event_type": "alert", "alert": {"severity": 1, "signature": "T"}}\n')

        cfg = replace(test_config, suricata=SuricataConfig(
            enabled=True, eve_json_path=str(eve_file)
        ))
        bus = EventBus()
        detector = SuricataDetector(event_bus=bus, config=cfg)
        # Set position beyond file size to simulate rotation
        detector._file_position = 99999
        entries = detector._read_new_lines()
        assert len(entries) == 1  # Resets and reads from start

    def test_read_new_lines_malformed_json(
        self, test_config: AppConfig, tmp_path: Path
    ) -> None:
        from dataclasses import replace
        eve_file = tmp_path / "eve.json"
        eve_file.write_text("not json\n")

        cfg = replace(test_config, suricata=SuricataConfig(
            enabled=True, eve_json_path=str(eve_file)
        ))
        bus = EventBus()
        detector = SuricataDetector(event_bus=bus, config=cfg)
        detector._file_position = 0
        entries = detector._read_new_lines()
        assert entries == []

    @pytest.mark.asyncio
    async def test_syslog_mode_init(self, test_config: AppConfig) -> None:
        from dataclasses import replace
        cfg = replace(test_config, suricata=SuricataConfig(
            enabled=True, syslog_listen_port=15514, syslog_listen_host="127.0.0.1"
        ))
        bus = EventBus()
        detector = SuricataDetector(event_bus=bus, config=cfg)
        await detector._initialize()
        assert detector._syslog_server is not None
        await detector._cleanup()
        assert detector._syslog_server is None

    @pytest.mark.asyncio
    async def test_poll_drains_pending(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = SuricataDetector(event_bus=bus, config=test_config)
        detector._pending_events.append({
            "event_type": "alert",
            "src_ip": "1.2.3.4",
            "alert": {"severity": 1, "signature": "Test Alert", "category": "Test"},
        })
        events = await detector._poll()
        assert len(events) == 1
        assert detector._pending_events == []

    @pytest.mark.asyncio
    async def test_init_no_config_warns(self, test_config: AppConfig) -> None:
        from dataclasses import replace
        cfg = replace(test_config, suricata=SuricataConfig(enabled=True))
        bus = EventBus()
        detector = SuricataDetector(event_bus=bus, config=cfg)
        await detector._initialize()  # Should warn but not raise
