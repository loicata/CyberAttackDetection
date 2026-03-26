"""Tests for detector modules."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from src.core.config import AppConfig
from src.core.enums import AlertType, DetectorState
from src.core.event_bus import EventBus
from src.core.models import RawEvent
from src.detectors.base import BaseDetector
from src.detectors.process_detector import ProcessDetector
from src.detectors.network_detector import NetworkDetector
from src.detectors.suricata_detector import SuricataDetector


# ---------------------------------------------------------------------------
# BaseDetector tests using a concrete stub
# ---------------------------------------------------------------------------

class StubDetector(BaseDetector):
    """Concrete stub for testing BaseDetector."""

    def __init__(
        self,
        event_bus: EventBus,
        events_to_return: list[list[RawEvent]] | None = None,
        fail_on_poll: bool = False,
    ) -> None:
        super().__init__(name="stub", event_bus=event_bus, polling_interval=0.05)
        self._events_queue = events_to_return or []
        self._poll_index = 0
        self._fail_on_poll = fail_on_poll

    async def _poll(self) -> list[RawEvent]:
        if self._fail_on_poll:
            raise RuntimeError("Simulated poll failure")
        if self._poll_index < len(self._events_queue):
            events = self._events_queue[self._poll_index]
            self._poll_index += 1
            return events
        return []


class TestBaseDetector:
    """Tests for the abstract BaseDetector."""

    def test_init_validates_name(self) -> None:
        bus = EventBus()
        with pytest.raises(ValueError, match="must not be empty"):
            BaseDetector.__init__(
                MagicMock(), name="", event_bus=bus, polling_interval=1.0
            )

    def test_init_validates_interval(self) -> None:
        bus = EventBus()
        with pytest.raises(ValueError, match="positive"):
            BaseDetector.__init__(
                MagicMock(), name="test", event_bus=bus, polling_interval=-1
            )

    @pytest.mark.asyncio
    async def test_start_and_stop(self) -> None:
        bus = EventBus()
        detector = StubDetector(event_bus=bus)
        await bus.start()
        await detector.start()
        assert detector.state == DetectorState.RUNNING
        await asyncio.sleep(0.1)
        await detector.stop()
        assert detector.state == DetectorState.STOPPED
        await bus.stop()

    @pytest.mark.asyncio
    async def test_publishes_events(self) -> None:
        bus = EventBus(max_queue_size=100)
        received: list[RawEvent] = []

        async def handler(event: RawEvent) -> None:
            received.append(event)

        bus.subscribe(handler)
        event = RawEvent(event_type=AlertType.PROCESS, data={"test": True})
        detector = StubDetector(event_bus=bus, events_to_return=[[event]])

        await bus.start()
        await detector.start()
        await asyncio.sleep(0.2)
        await detector.stop()
        await bus.stop()

        assert len(received) >= 1
        assert received[0].data == {"test": True}

    @pytest.mark.asyncio
    async def test_error_threshold(self) -> None:
        bus = EventBus()
        detector = StubDetector(event_bus=bus, fail_on_poll=True)
        # Override error threshold implicitly via repeated failures
        await bus.start()
        await detector.start()
        await asyncio.sleep(1.0)  # Let it fail many times
        await detector.stop()
        await bus.stop()
        assert detector._error_count > 0

    def test_health_check(self) -> None:
        bus = EventBus()
        detector = StubDetector(event_bus=bus)
        health = detector.health_check()
        assert health["name"] == "stub"
        assert health["state"] == "stopped"


# ---------------------------------------------------------------------------
# ProcessDetector tests
# ---------------------------------------------------------------------------

class TestProcessDetector:
    """Tests for ProcessDetector with mocked psutil."""

    @pytest.fixture
    def mock_config(self, test_config: AppConfig) -> AppConfig:
        return test_config

    def test_detects_suspicious_process_name(self, mock_config: AppConfig) -> None:
        bus = EventBus(max_queue_size=100)
        detector = ProcessDetector(event_bus=bus, config=mock_config)

        # Directly test the detection logic via _check_new_process
        proc_info = {
            "pid": 999, "name": "mimikatz.exe", "ppid": 1,
            "exe": None, "username": "user", "cpu_percent": 15.0,
            "memory_mb": 30.0, "create_time": 0, "cmdline": ["mimikatz.exe"],
        }

        events = detector._check_new_process(proc_info, "mimikatz.exe")
        malware_events = [e for e in events if e.data.get("rule") == "known_malware_name"]
        assert len(malware_events) == 1
        assert malware_events[0].process_name == "mimikatz.exe"
        assert malware_events[0].process_pid == 999

    @pytest.mark.asyncio
    async def test_detects_suspicious_parent_child(self, mock_config: AppConfig) -> None:
        bus = EventBus(max_queue_size=100)
        received: list[RawEvent] = []

        async def handler(event: RawEvent) -> None:
            received.append(event)

        bus.subscribe(handler)
        detector = ProcessDetector(event_bus=bus, config=mock_config)

        initial = [
            {"pid": 1, "name": "explorer.exe", "ppid": 0, "exe": None,
             "username": "u", "cpu_percent": 0, "memory_info": None,
             "create_time": 0, "cmdline": []},
            {"pid": 100, "name": "winword.exe", "ppid": 1, "exe": None,
             "username": "u", "cpu_percent": 0, "memory_info": None,
             "create_time": 0, "cmdline": []},
        ]
        with_child = initial + [
            {"pid": 200, "name": "cmd.exe", "ppid": 100, "exe": None,
             "username": "u", "cpu_percent": 0, "memory_info": None,
             "create_time": 0, "cmdline": []},
        ]

        def to_snapshot(procs: list) -> list:
            return [
                {"pid": p["pid"], "name": p["name"], "ppid": p["ppid"],
                 "exe": p["exe"], "username": p["username"],
                 "cpu_percent": p["cpu_percent"], "memory_mb": 0.0,
                 "create_time": 0, "cmdline": p.get("cmdline")}
                for p in procs
            ]

        snapshots = iter([to_snapshot(initial), to_snapshot(with_child)])

        with patch.object(
            ProcessDetector, "_snapshot_processes", side_effect=lambda: next(snapshots)
        ):
            await bus.start()
            await detector.start()
            await asyncio.sleep(0.3)
            await detector.stop()
            await bus.stop()

        pc_events = [e for e in received if e.data.get("rule") == "suspicious_parent_child"]
        assert len(pc_events) >= 1


# ---------------------------------------------------------------------------
# NetworkDetector tests
# ---------------------------------------------------------------------------

class TestNetworkDetector:
    """Tests for NetworkDetector with mocked psutil."""

    @pytest.mark.asyncio
    async def test_detects_suspicious_port(self, test_config: AppConfig) -> None:
        bus = EventBus(max_queue_size=100)
        received: list[RawEvent] = []

        async def handler(event: RawEvent) -> None:
            received.append(event)

        bus.subscribe(handler)
        detector = NetworkDetector(event_bus=bus, config=test_config)

        initial_conns: list[dict] = []
        suspicious_conns = [{
            "local_address": "192.168.1.10",
            "local_port": 49000,
            "remote_address": "203.0.113.50",
            "remote_port": 4444,
            "status": "ESTABLISHED",
            "pid": 999,
            "process_name": "evil.exe",
            "family": "AF_INET",
        }]

        snapshots = iter([initial_conns, suspicious_conns])

        with patch.object(
            NetworkDetector, "_get_connections", side_effect=lambda: next(snapshots)
        ):
            await bus.start()
            await detector.start()
            await asyncio.sleep(0.3)
            await detector.stop()
            await bus.stop()

        port_events = [
            e for e in received if e.data.get("rule") == "suspicious_port_connection"
        ]
        assert len(port_events) >= 1
        assert port_events[0].dest_port == 4444

    @pytest.mark.asyncio
    async def test_detects_new_listening_port(self, test_config: AppConfig) -> None:
        bus = EventBus(max_queue_size=100)
        received: list[RawEvent] = []

        async def handler(event: RawEvent) -> None:
            received.append(event)

        bus.subscribe(handler)
        detector = NetworkDetector(event_bus=bus, config=test_config)

        initial: list[dict] = []
        with_listener = [{
            "local_address": "0.0.0.0",
            "local_port": 9999,
            "remote_address": "",
            "remote_port": 0,
            "status": "LISTEN",
            "pid": 555,
            "process_name": "backdoor.exe",
            "family": "AF_INET",
        }]

        snapshots = iter([initial, with_listener])

        with patch.object(
            NetworkDetector, "_get_connections", side_effect=lambda: next(snapshots)
        ):
            await bus.start()
            await detector.start()
            await asyncio.sleep(0.3)
            await detector.stop()
            await bus.stop()

        listen_events = [
            e for e in received if e.data.get("rule") == "new_listening_port"
        ]
        assert len(listen_events) >= 1


# ---------------------------------------------------------------------------
# SuricataDetector tests
# ---------------------------------------------------------------------------

class TestSuricataDetector:
    """Tests for SuricataDetector."""

    def test_parse_eve_alert(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = SuricataDetector(event_bus=bus, config=test_config)

        entry = {
            "event_type": "alert",
            "src_ip": "192.168.1.10",
            "src_port": 49200,
            "dest_ip": "185.100.87.42",
            "dest_port": 443,
            "alert": {
                "signature_id": 2024792,
                "signature": "ET MALWARE Win32/Emotet",
                "category": "A Network Trojan was detected",
                "severity": 1,
                "action": "allowed",
            },
        }

        event = detector._parse_eve_entry(entry)
        assert event is not None
        assert event.event_type == AlertType.SURICATA
        assert event.data["rule"] == "suricata_high_severity"
        assert event.source_ip == "192.168.1.10"
        assert event.dest_port == 443

    def test_parse_eve_flow_ignored(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = SuricataDetector(event_bus=bus, config=test_config)

        entry = {"event_type": "flow", "src_ip": "1.2.3.4"}
        event = detector._parse_eve_entry(entry)
        assert event is None

    def test_parse_medium_severity(self, test_config: AppConfig) -> None:
        bus = EventBus()
        detector = SuricataDetector(event_bus=bus, config=test_config)

        entry = {
            "event_type": "alert",
            "src_ip": "10.0.0.1",
            "alert": {"severity": 2, "signature": "Test", "category": "Test"},
        }

        event = detector._parse_eve_entry(entry)
        assert event is not None
        assert event.data["rule"] == "suricata_medium_severity"

    @pytest.mark.asyncio
    async def test_file_mode_reads_new_lines(
        self, test_config: AppConfig, tmp_path: Path
    ) -> None:
        eve_file = tmp_path / "eve.json"
        alert_line = json.dumps({
            "event_type": "alert",
            "src_ip": "1.2.3.4",
            "dest_ip": "5.6.7.8",
            "alert": {"severity": 1, "signature": "Test", "category": "Test"},
        })
        eve_file.write_text(alert_line + "\n")

        # Create a config with suricata enabled
        from dataclasses import replace
        from src.core.config import SuricataConfig
        suricata_cfg = SuricataConfig(
            enabled=True, eve_json_path=str(eve_file),
        )
        cfg = replace(test_config, suricata=suricata_cfg)

        bus = EventBus(max_queue_size=100)
        received: list[RawEvent] = []

        async def handler(event: RawEvent) -> None:
            received.append(event)

        bus.subscribe(handler)
        detector = SuricataDetector(event_bus=bus, config=cfg)

        await bus.start()
        await detector._initialize()

        # Write new line after init (simulating new alert)
        with open(eve_file, "a") as f:
            f.write(alert_line + "\n")

        events = await detector._poll()
        assert len(events) == 1
        assert events[0].data["rule"] == "suricata_high_severity"
        await bus.stop()
