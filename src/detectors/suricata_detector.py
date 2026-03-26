"""Optional Suricata eve.json log ingestion.

Supports two modes:
1. File watching: Tail eve.json via watchdog (for shared file / local file)
2. Syslog TCP: Listen on a TCP port for syslog-formatted JSON

Both modes are disabled by default and must be explicitly enabled in config.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from pathlib import Path
from typing import Any

from src.core.config import AppConfig
from src.core.enums import AlertType
from src.core.event_bus import EventBus
from src.core.models import RawEvent
from src.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class SuricataDetector(BaseDetector):
    """Ingest Suricata eve.json alerts.

    Can operate in file-watching mode or syslog-receiving mode.

    Args:
        event_bus: Event bus to publish detected events.
        config: Application configuration.
    """

    def __init__(self, event_bus: EventBus, config: AppConfig) -> None:
        super().__init__(
            name="suricata_detector",
            event_bus=event_bus,
            polling_interval=config.polling_interval_seconds,
        )
        self._config = config
        self._eve_path = config.suricata.eve_json_path
        self._syslog_port = config.suricata.syslog_listen_port
        self._syslog_host = config.suricata.syslog_listen_host
        self._file_position: int = 0
        self._pending_events: list[dict[str, Any]] = []
        self._syslog_server: asyncio.AbstractServer | None = None

    # Common Suricata eve.json locations on Windows
    _DEFAULT_EVE_PATHS = [
        r"C:\Program Files\Suricata\log\eve.json",
        r"C:\Program Files\Suricata\eve.json",
        r"C:\Suricata\log\eve.json",
        r"C:\Suricata\eve.json",
    ]

    async def _initialize(self) -> None:
        """Set up file watcher or syslog listener based on config.

        If no eve_json_path is configured, tries to auto-detect
        Suricata's eve.json in standard installation paths.
        """
        # Auto-detect eve.json if not configured
        if not self._eve_path:
            self._eve_path = self._auto_detect_eve_json()

        if self._eve_path:
            await self._init_file_mode()
        elif self._syslog_port > 0:
            await self._init_syslog_mode()
        else:
            logger.warning(
                "Suricata detector enabled but eve.json not found and no syslog port configured"
            )

    def _auto_detect_eve_json(self) -> str:
        """Try to find eve.json in standard Suricata locations.

        Returns:
            Path to eve.json if found, empty string otherwise.
        """
        for path_str in self._DEFAULT_EVE_PATHS:
            path = Path(path_str)
            if path.exists():
                logger.info("Auto-detected Suricata eve.json: %s", path_str)
                return path_str

        logger.debug("Suricata eve.json not found in standard locations")
        return ""

    async def _init_file_mode(self) -> None:
        """Initialize file-watching mode for eve.json."""
        path = Path(self._eve_path)
        if not path.exists():
            logger.warning("Suricata eve.json not found at %s, will retry", self._eve_path)
            self._file_position = 0
            return

        self._file_position = path.stat().st_size
        logger.info(
            "Suricata file mode: watching %s (starting at byte %d)",
            self._eve_path,
            self._file_position,
        )

    async def _init_syslog_mode(self) -> None:
        """Initialize syslog TCP listener mode."""
        self._syslog_server = await asyncio.start_server(
            self._handle_syslog_client,
            self._syslog_host,
            self._syslog_port,
        )
        logger.info(
            "Suricata syslog mode: listening on %s:%d",
            self._syslog_host,
            self._syslog_port,
        )

    async def _cleanup(self) -> None:
        """Stop syslog server if running."""
        if self._syslog_server is not None:
            self._syslog_server.close()
            await self._syslog_server.wait_closed()
            self._syslog_server = None

    async def _poll(self) -> list[RawEvent]:
        """Read new events from file or pending syslog queue.

        Returns:
            List of RawEvent from Suricata alerts.
        """
        events: list[RawEvent] = []

        if self._eve_path:
            new_entries = await asyncio.to_thread(self._read_new_lines)
            for entry in new_entries:
                event = self._parse_eve_entry(entry)
                if event is not None:
                    events.append(event)

        pending = self._pending_events[:]
        self._pending_events.clear()
        for entry in pending:
            event = self._parse_eve_entry(entry)
            if event is not None:
                events.append(event)

        return events

    def _read_new_lines(self) -> list[dict[str, Any]]:
        """Read new lines from eve.json since last position.

        Returns:
            List of parsed JSON entries.
        """
        path = Path(self._eve_path)
        if not path.exists():
            return []

        current_size = path.stat().st_size
        if current_size < self._file_position:
            logger.info("Eve.json was rotated, resetting position")
            self._file_position = 0

        if current_size <= self._file_position:
            return []

        entries: list[dict[str, Any]] = []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                fh.seek(self._file_position)
                raw_lines = fh.readlines()
                new_position = fh.tell()

            alert_count = 0
            skipped_internal = 0
            for line in raw_lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    entries.append(entry)
                    if entry.get("event_type") == "alert":
                        sig = entry.get("alert", {}).get("signature", "")
                        if sig.startswith("SURICATA "):
                            skipped_internal += 1
                        else:
                            alert_count += 1
                except json.JSONDecodeError:
                    logger.debug("Skipping malformed JSON line in eve.json")

            if raw_lines:
                logger.info(
                    "Eve.json read %d lines (%d bytes), %d alerts, %d internal skipped",
                    len(raw_lines),
                    new_position - self._file_position,
                    alert_count,
                    skipped_internal,
                )
            self._file_position = new_position

        except OSError as exc:
            logger.error("Failed to read eve.json: %s", exc)

        return entries

    async def _handle_syslog_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single syslog TCP client connection.

        Args:
            reader: Async stream reader.
            writer: Async stream writer.
        """
        peer = writer.get_extra_info("peername")
        logger.info("Syslog client connected: %s", peer)

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                try:
                    entry = json.loads(text)
                    self._pending_events.append(entry)
                except json.JSONDecodeError:
                    logger.debug("Non-JSON syslog line from %s", peer)
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            logger.info("Syslog client disconnected: %s", peer)

    def _parse_eve_entry(self, entry: dict[str, Any]) -> RawEvent | None:
        """Convert a Suricata eve.json entry to a RawEvent.

        Only alert-type entries are converted. Flow records and
        other non-alert types are ignored.

        Args:
            entry: Parsed JSON entry from eve.json.

        Returns:
            RawEvent if this is an alert, None otherwise.
        """
        event_type = entry.get("event_type")
        if event_type != "alert":
            return None

        alert_data = entry.get("alert", {})

        # Skip internal Suricata decoder alerts (checksum, truncated, etc.)
        # These are noise from checksum offloading, not real threats.
        signature = alert_data.get("signature", "")
        if signature.startswith("SURICATA "):
            return None

        severity = alert_data.get("severity", 3)

        is_high_severity = severity == 1
        rule = "suricata_high_severity" if is_high_severity else "suricata_medium_severity"

        src_ip = entry.get("src_ip")
        src_port = entry.get("src_port")
        dest_ip = entry.get("dest_ip")
        dest_port = entry.get("dest_port")

        return RawEvent(
            event_type=AlertType.SURICATA,
            data={
                "rule": rule,
                "signature_id": alert_data.get("signature_id"),
                "signature": alert_data.get("signature", "Unknown"),
                "category": alert_data.get("category", "Unknown"),
                "severity": severity,
                "action": alert_data.get("action"),
                "raw_entry": entry,
            },
            source_ip=src_ip,
            source_port=src_port,
            dest_ip=dest_ip,
            dest_port=dest_port,
        )
