"""Windows Event Log monitor with Sysmon integration.

Detects security-relevant events using wevtutil command-line tool.

Monitors Windows Security/System events:
- Failed/successful logons (4624, 4625)
- Process creation (4688), service installs (7045)
- Log clearing (1102), privilege escalation (4672)

Monitors Sysmon events (if installed):
- Sysmon 1: Process creation with hashes and command line
- Sysmon 3: Network connection with process context
- Sysmon 5: Process terminated
- Sysmon 6: Driver loaded
- Sysmon 7: Image loaded (DLL injection detection)
- Sysmon 8: CreateRemoteThread (code injection)
- Sysmon 10: Process access (credential dumping)
- Sysmon 11: File creation in monitored paths
- Sysmon 12/13: Registry key/value create/modify
- Sysmon 15: Alternate Data Stream creation
- Sysmon 17: Named pipe created
- Sysmon 22: DNS query logged
- Sysmon 23/26: File delete
- Sysmon 25: Process tampering (process hollowing/herpaderping)
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from src.core.subprocess_utils import run_silent
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any

from src.core.config import AppConfig
from src.core.enums import AlertType
from src.core.event_bus import EventBus
from src.core.models import RawEvent
from src.detectors.base import BaseDetector

logger = logging.getLogger(__name__)

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_SECONDS = 60

# Sysmon Event IDs and their meaning
SYSMON_EVENT_IDS = {
    1: "sysmon_process_create",
    3: "sysmon_network_connect",
    5: "sysmon_process_terminate",
    6: "sysmon_driver_loaded",
    7: "sysmon_image_loaded",
    8: "sysmon_create_remote_thread",
    10: "sysmon_process_access",
    11: "sysmon_file_create",
    12: "sysmon_registry_event",
    13: "sysmon_registry_value_set",
    15: "sysmon_file_stream_create",
    17: "sysmon_pipe_created",
    22: "sysmon_dns_query",
    23: "sysmon_file_delete",
    25: "sysmon_process_tampering",
    26: "sysmon_file_delete",
}

# Suspicious indicators for Sysmon event enrichment
SUSPICIOUS_IMAGE_LOADS = {
    "amsi.dll", "clr.dll", "mscoree.dll",  # .NET in unexpected process
}

SUSPICIOUS_PIPE_NAMES = {
    "\\psexec", "\\msagent_", "\\cobaltstrike",
    "\\meterpreter", "\\nanodump", "\\lsadump",
}

SUSPICIOUS_DNS_DOMAINS = {
    ".onion", ".bit", ".bazar", ".coin",
}

# Registry paths indicating persistence
PERSISTENCE_REGISTRY_PATHS = {
    "\\currentversion\\run",
    "\\currentversion\\runonce",
    "\\currentversion\\winlogon",
    "\\currentversion\\image file execution",
    "\\currentcontrolset\\services",
    "\\policies\\explorer\\run",
}


class EventLogDetector(BaseDetector):
    """Monitor Windows Event Logs and Sysmon for security-relevant events.

    Args:
        event_bus: Event bus to publish detected events.
        config: Application configuration.
    """

    def __init__(self, event_bus: EventBus, config: AppConfig) -> None:
        super().__init__(
            name="eventlog_detector",
            event_bus=event_bus,
            polling_interval=config.polling_interval_seconds,
        )
        self._config = config
        self._channels = config.eventlog_channels
        self._event_ids = set(config.event_ids_of_interest)
        self._sysmon_enabled = config.sysmon_enabled
        self._last_poll_time: datetime = datetime.now(timezone.utc)
        self._failed_logins: dict[str, list[datetime]] = {}

    async def _initialize(self) -> None:
        """Set initial poll time to now to avoid processing old events."""
        self._last_poll_time = datetime.now(timezone.utc)

        # Auto-detect Sysmon if not explicitly configured
        if not self._sysmon_enabled:
            self._sysmon_enabled = await asyncio.to_thread(self._detect_sysmon)

        if self._sysmon_enabled:
            sysmon_channel = "Microsoft-Windows-Sysmon/Operational"
            if sysmon_channel not in self._channels:
                self._channels = tuple(self._channels) + (sysmon_channel,)
            # Add Sysmon event IDs
            self._event_ids.update(SYSMON_EVENT_IDS.keys())
            logger.info("Sysmon detected and enabled — monitoring %d Sysmon event types",
                        len(SYSMON_EVENT_IDS))

        logger.info(
            "EventLog detector initialized. Channels: %s, Event IDs: %d types, Sysmon: %s",
            self._channels, len(self._event_ids),
            "enabled" if self._sysmon_enabled else "disabled",
        )

    @staticmethod
    def _detect_sysmon() -> bool:
        """Check if Sysmon is installed by querying its event log."""
        try:
            result = run_silent(
                ["wevtutil", "gl", "Microsoft-Windows-Sysmon/Operational"],
                timeout=5,
            )
            is_installed = result.returncode == 0
            if is_installed:
                logger.info("Sysmon auto-detected on this system")
            return is_installed
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    async def _poll(self) -> list[RawEvent]:
        """Query Windows Event Logs for new events.

        Returns:
            List of RawEvent for security-relevant events.
        """
        events: list[RawEvent] = []
        poll_start = self._last_poll_time
        poll_end = datetime.now(timezone.utc)

        for channel in self._channels:
            try:
                channel_events = await asyncio.to_thread(
                    self._query_channel, channel, poll_start
                )
                events.extend(channel_events)
            except Exception:
                logger.exception("Failed to query channel %s", channel)

        self._last_poll_time = poll_end
        return events

    def _query_channel(self, channel: str, since: datetime) -> list[RawEvent]:
        """Query a specific event log channel using wevtutil.

        Args:
            channel: Event log channel name.
            since: Only return events after this time.

        Returns:
            List of RawEvent from this channel.
        """
        time_str = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        event_id_filter = " or ".join(f"EventID={eid}" for eid in sorted(self._event_ids))
        xpath = (
            f"*[System[({event_id_filter}) and "
            f"TimeCreated[@SystemTime>='{time_str}']]]"
        )

        try:
            result = run_silent(
                ["wevtutil", "qe", channel, "/q:" + xpath, "/f:xml", "/rd:true"],
                timeout=30,
            )
        except FileNotFoundError:
            logger.error("wevtutil not found. Windows Event Log monitoring unavailable.")
            return []
        except subprocess.TimeoutExpired:
            logger.error("wevtutil query timed out for channel %s", channel)
            return []

        if result.returncode != 0:
            stderr = result.stderr.strip()
            if stderr:
                logger.debug("wevtutil stderr for %s: %s", channel, stderr)
            return []

        return self._parse_xml_events(result.stdout, channel)

    def _parse_xml_events(self, xml_output: str, channel: str) -> list[RawEvent]:
        """Parse wevtutil XML output into RawEvents."""
        if not xml_output.strip():
            return []

        wrapped = f"<Events>{xml_output}</Events>"
        events: list[RawEvent] = []

        try:
            root = ET.fromstring(wrapped)
        except ET.ParseError:
            logger.error("Failed to parse XML from channel %s", channel)
            return []

        for event_elem in root.findall("e:Event", NS):
            parsed = self._parse_single_event(event_elem, channel)
            if parsed is not None:
                events.append(parsed)

        return events

    def _parse_single_event(
        self, event_elem: ET.Element, channel: str
    ) -> RawEvent | None:
        """Parse a single <Event> XML element."""
        system = event_elem.find("e:System", NS)
        if system is None:
            return None

        event_id_elem = system.find("e:EventID", NS)
        if event_id_elem is None or event_id_elem.text is None:
            return None

        try:
            event_id = int(event_id_elem.text)
        except ValueError:
            return None

        if event_id not in self._event_ids:
            return None

        event_data = self._extract_event_data(event_elem)
        event_data["event_id"] = event_id
        event_data["channel"] = channel

        is_sysmon = event_id in SYSMON_EVENT_IDS
        if is_sysmon:
            return self._build_sysmon_event(event_id, event_data)
        return self._build_standard_event(event_id, event_data)

    def _extract_event_data(self, event_elem: ET.Element) -> dict[str, Any]:
        """Extract key-value pairs from EventData section."""
        data: dict[str, Any] = {}
        event_data = event_elem.find("e:EventData", NS)
        if event_data is not None:
            for data_item in event_data.findall("e:Data", NS):
                name = data_item.get("Name", "")
                value = data_item.text or ""
                if name:
                    data[name] = value
        return data

    # ------------------------------------------------------------------
    # Standard Windows events
    # ------------------------------------------------------------------

    def _build_standard_event(
        self, event_id: int, data: dict[str, Any]
    ) -> RawEvent:
        """Build a RawEvent from a standard Windows event."""
        rule = self._classify_standard_event(event_id, data)
        data["rule"] = rule

        source_ip = data.get("IpAddress") or data.get("SourceNetworkAddress")

        return RawEvent(
            event_type=AlertType.EVENTLOG,
            data=data,
            source_ip=source_ip if source_ip and source_ip != "-" else None,
        )

    def _classify_standard_event(self, event_id: int, data: dict[str, Any]) -> str:
        """Determine the scoring rule for a standard Windows event."""
        if event_id == 1102:
            return "log_clearing"
        if event_id == 7045:
            return "new_service_installed"
        if event_id == 4625:
            self._track_failed_login(data)
            return "eventlog_critical_event"
        if event_id in (4624, 4648, 4672):
            return "eventlog_critical_event"
        if event_id == 4688:
            return "eventlog_critical_event"
        if event_id in (4697, 4698, 4702):
            return "new_service_installed"
        return "eventlog_critical_event"

    # ------------------------------------------------------------------
    # Sysmon events
    # ------------------------------------------------------------------

    def _build_sysmon_event(
        self, event_id: int, data: dict[str, Any]
    ) -> RawEvent:
        """Build a RawEvent from a Sysmon event with enriched context.

        Args:
            event_id: Sysmon event ID (1-26).
            data: Parsed event data fields.

        Returns:
            RawEvent with appropriate rule, process, network, and file info.
        """
        rule = self._classify_sysmon_event(event_id, data)
        data["rule"] = rule
        data["sysmon_event_id"] = event_id

        # Extract common fields from Sysmon data
        process_name = self._extract_filename(
            data.get("Image") or data.get("SourceImage") or ""
        )
        process_pid = self._safe_int(data.get("ProcessId"))
        source_ip = data.get("SourceIp")
        source_port = self._safe_int(data.get("SourcePort"))
        dest_ip = data.get("DestinationIp")
        dest_port = self._safe_int(data.get("DestinationPort"))
        file_path = data.get("TargetFilename") or data.get("TargetObject")

        return RawEvent(
            event_type=AlertType.EVENTLOG,
            data=data,
            process_name=process_name or None,
            process_pid=process_pid,
            source_ip=source_ip if source_ip and source_ip != "-" else None,
            source_port=source_port,
            dest_ip=dest_ip if dest_ip and dest_ip != "-" else None,
            dest_port=dest_port,
            file_path=file_path,
        )

    def _classify_sysmon_event(self, event_id: int, data: dict[str, Any]) -> str:
        """Determine the scoring rule for a Sysmon event.

        Applies heuristics to distinguish benign from suspicious
        Sysmon events using contextual data.

        Args:
            event_id: Sysmon event ID.
            data: Parsed event data.

        Returns:
            Rule name string for the scorer.
        """
        # Sysmon 1: Process creation
        if event_id == 1:
            return self._classify_sysmon_process_create(data)

        # Sysmon 3: Network connection
        if event_id == 3:
            return self._classify_sysmon_network(data)

        # Sysmon 6: Driver loaded
        if event_id == 6:
            is_signed = data.get("Signed", "").lower() == "true"
            return "sysmon_driver_loaded" if not is_signed else "sysmon_driver_loaded_signed"

        # Sysmon 7: Image (DLL) loaded
        if event_id == 7:
            return self._classify_sysmon_image_loaded(data)

        # Sysmon 8: CreateRemoteThread — ALWAYS suspicious
        if event_id == 8:
            return "sysmon_create_remote_thread"

        # Sysmon 10: Process access (credential dumping patterns)
        if event_id == 10:
            return self._classify_sysmon_process_access(data)

        # Sysmon 11: File creation
        if event_id == 11:
            return self._classify_sysmon_file_create(data)

        # Sysmon 12/13: Registry events
        if event_id in (12, 13):
            return self._classify_sysmon_registry(data)

        # Sysmon 15: Alternate Data Stream (ADS)
        if event_id == 15:
            return "sysmon_ads_created"

        # Sysmon 17: Named pipe
        if event_id == 17:
            return self._classify_sysmon_pipe(data)

        # Sysmon 22: DNS query
        if event_id == 22:
            return self._classify_sysmon_dns(data)

        # Sysmon 25: Process tampering — ALWAYS high severity
        if event_id == 25:
            return "sysmon_process_tampering"

        # Sysmon 5 (process terminate), 23/26 (file delete): low interest
        return SYSMON_EVENT_IDS.get(event_id, "sysmon_generic")

    def _classify_sysmon_process_create(self, data: dict[str, Any]) -> str:
        """Classify Sysmon process creation event."""
        image = (data.get("Image") or "").lower()
        parent = (data.get("ParentImage") or "").lower()
        cmdline = (data.get("CommandLine") or "").lower()

        # Check for suspicious process names
        image_name = self._extract_filename(image).lower()
        name_no_ext = image_name.rsplit(".", 1)[0] if "." in image_name else image_name
        is_malware_name = (
            image_name in {n.lower() for n in self._config.suspicious_process_names}
            or name_no_ext in {n.lower() for n in self._config.suspicious_process_names}
        )
        if is_malware_name:
            return "known_malware_name"

        # Check suspicious parent-child
        parent_name = self._extract_filename(parent).lower()
        for p, c in self._config.suspicious_parent_child:
            if parent_name == p.lower() and image_name == c.lower():
                return "suspicious_parent_child"

        # Check for encoded PowerShell commands
        has_encoded_cmd = (
            "powershell" in image and
            ("-enc" in cmdline or "-encodedcommand" in cmdline or "frombase64" in cmdline)
        )
        if has_encoded_cmd:
            return "sysmon_encoded_powershell"

        # Check for commands run from suspicious locations
        is_suspicious_path = any(
            p in image for p in ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                                  "\\downloads\\", "\\public\\")
        )
        if is_suspicious_path:
            return "sysmon_suspicious_exec_path"

        return "sysmon_process_create"

    def _classify_sysmon_network(self, data: dict[str, Any]) -> str:
        """Classify Sysmon network connection event."""
        dest_port = self._safe_int(data.get("DestinationPort"))
        dest_ip = data.get("DestinationIp", "")

        if dest_port and dest_port in set(self._config.suspicious_ports):
            return "suspicious_port_connection"

        # Connections to external IPs from unusual processes
        image = (data.get("Image") or "").lower()
        is_unusual_network_process = any(
            p in image for p in ("powershell", "cmd.exe", "wscript", "cscript",
                                  "mshta", "regsvr32", "rundll32")
        )
        if is_unusual_network_process and dest_ip and not self._is_private_ip(dest_ip):
            return "sysmon_suspicious_network"

        return "sysmon_network_connect"

    def _classify_sysmon_image_loaded(self, data: dict[str, Any]) -> str:
        """Classify Sysmon image (DLL) loaded event."""
        image_loaded = (data.get("ImageLoaded") or "").lower()
        loaded_name = self._extract_filename(image_loaded).lower()

        is_signed = data.get("Signed", "").lower() == "true"
        if loaded_name in SUSPICIOUS_IMAGE_LOADS and not is_signed:
            return "sysmon_suspicious_dll_load"

        if not is_signed:
            return "sysmon_unsigned_dll_load"

        return "sysmon_image_loaded"

    def _classify_sysmon_process_access(self, data: dict[str, Any]) -> str:
        """Classify Sysmon process access event."""
        target = (data.get("TargetImage") or "").lower()
        source = (data.get("SourceImage") or "").lower()

        # Accessing lsass.exe = credential dumping attempt
        is_lsass_access = "lsass.exe" in target
        is_system_tool = any(p in source for p in ("svchost", "csrss", "lsass", "services"))

        if is_lsass_access and not is_system_tool:
            return "sysmon_lsass_access"

        return "sysmon_process_access"

    def _classify_sysmon_file_create(self, data: dict[str, Any]) -> str:
        """Classify Sysmon file creation event."""
        target = (data.get("TargetFilename") or "").lower()

        is_in_startup = any(p in target for p in (
            "\\startup\\", "\\start menu\\programs\\startup",
        ))
        if is_in_startup:
            return "sysmon_startup_file_create"

        is_in_system32 = "\\system32\\" in target or "\\syswow64\\" in target
        if is_in_system32:
            return "filesystem_change_system32"

        return "sysmon_file_create"

    def _classify_sysmon_registry(self, data: dict[str, Any]) -> str:
        """Classify Sysmon registry event."""
        target_object = (data.get("TargetObject") or "").lower()

        is_persistence = any(p in target_object for p in PERSISTENCE_REGISTRY_PATHS)
        if is_persistence:
            return "sysmon_registry_persistence"

        return "sysmon_registry_event"

    def _classify_sysmon_pipe(self, data: dict[str, Any]) -> str:
        """Classify Sysmon named pipe creation event."""
        pipe_name = (data.get("PipeName") or "").lower()

        is_suspicious = any(p in pipe_name for p in SUSPICIOUS_PIPE_NAMES)
        if is_suspicious:
            return "sysmon_suspicious_pipe"

        return "sysmon_pipe_created"

    def _classify_sysmon_dns(self, data: dict[str, Any]) -> str:
        """Classify Sysmon DNS query event."""
        query = (data.get("QueryName") or "").lower()

        is_suspicious_tld = any(query.endswith(tld) for tld in SUSPICIOUS_DNS_DOMAINS)
        if is_suspicious_tld:
            return "sysmon_suspicious_dns"

        # Very long domain names could indicate DNS tunneling
        is_very_long = len(query) > 60
        if is_very_long:
            return "sysmon_dns_tunneling"

        return "sysmon_dns_query"

    # ------------------------------------------------------------------
    # Brute force tracking
    # ------------------------------------------------------------------

    def _track_failed_login(self, data: dict[str, Any]) -> str | None:
        """Track failed logins for brute-force detection."""
        source_ip = data.get("IpAddress") or data.get("SourceNetworkAddress", "unknown")
        now = datetime.now(timezone.utc)

        if source_ip not in self._failed_logins:
            self._failed_logins[source_ip] = []

        self._failed_logins[source_ip].append(now)

        cutoff = now - timedelta(seconds=FAILED_LOGIN_WINDOW_SECONDS)
        self._failed_logins[source_ip] = [
            t for t in self._failed_logins[source_ip] if t > cutoff
        ]

        threshold_exceeded = len(self._failed_logins[source_ip]) >= FAILED_LOGIN_THRESHOLD
        if threshold_exceeded:
            logger.warning(
                "Multiple failed logins from %s: %d in %ds",
                source_ip, len(self._failed_logins[source_ip]),
                FAILED_LOGIN_WINDOW_SECONDS,
            )
            return "multiple_failed_logins"

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_filename(path: str) -> str:
        """Extract filename from a full path.

        Args:
            path: Full file path.

        Returns:
            Filename only (e.g., 'cmd.exe' from 'C:\\Windows\\System32\\cmd.exe').
        """
        if not path:
            return ""
        # Handle both \ and /
        parts = path.replace("/", "\\").rsplit("\\", 1)
        return parts[-1] if parts else path

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        """Convert a value to int or return None."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Check if an IP is private/RFC1918."""
        import ipaddress
        try:
            return ipaddress.ip_address(ip_str).is_private
        except ValueError:
            return False
