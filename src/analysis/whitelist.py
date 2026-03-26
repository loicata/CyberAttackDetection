"""Whitelist manager for known-good entities.

Manages process names, IP addresses, file hashes, and paths
that should be considered safe and reduce alert scoring.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any

from src.core.config import AppConfig
from src.core.database import Database
from src.core.models import RawEvent

logger = logging.getLogger(__name__)


class WhitelistManager:
    """Manage whitelists for false-positive reduction.

    Args:
        database: Database instance for persistence.
        config: Application configuration.
    """

    def __init__(self, database: Database, config: AppConfig) -> None:
        if not isinstance(database, Database):
            raise TypeError(f"Expected Database, got {type(database).__name__}")
        self._db = database
        self._config = config
        self._process_cache: set[str] = set()
        self._ip_cache: set[str] = set()
        self._ip_ranges: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._hash_cache: set[str] = set()
        self._path_cache: set[str] = set()

    def initialize(self) -> None:
        """Load defaults from config and existing entries from database."""
        self._load_defaults()
        self._load_from_database()
        logger.info(
            "Whitelist initialized: %d processes, %d IPs, %d IP ranges, "
            "%d hashes, %d paths",
            len(self._process_cache),
            len(self._ip_cache),
            len(self._ip_ranges),
            len(self._hash_cache),
            len(self._path_cache),
        )

    def _load_defaults(self) -> None:
        """Load default whitelist entries from configuration."""
        defaults = self._config.analysis.whitelist_defaults
        for proc in defaults.get("trusted_processes", []):
            self._process_cache.add(proc.lower())

        for ip_range in defaults.get("trusted_ip_ranges", []):
            try:
                network = ipaddress.ip_network(ip_range, strict=False)
                self._ip_ranges.append(network)
            except ValueError:
                logger.warning("Invalid IP range in whitelist defaults: %s", ip_range)

    def _load_from_database(self) -> None:
        """Load existing whitelist entries from the database."""
        entries = self._db.get_whitelist()
        for entry in entries:
            entry_type = entry["entry_type"]
            value = entry["value"]
            if entry_type == "process":
                self._process_cache.add(value.lower())
            elif entry_type == "ip":
                self._ip_cache.add(value)
            elif entry_type == "hash":
                self._hash_cache.add(value.lower())
            elif entry_type == "path":
                self._path_cache.add(value.lower())

    def is_whitelisted(self, event: RawEvent) -> bool:
        """Check if any entity in the event is whitelisted.

        Args:
            event: The raw event to check.

        Returns:
            True if any entity in the event matches the whitelist.
        """
        if event.process_name:
            is_process_wl = self._is_process_whitelisted(event.process_name)
            if is_process_wl:
                return True

        if event.source_ip:
            is_src_wl = self._is_ip_whitelisted(event.source_ip)
            if is_src_wl:
                return True

        if event.dest_ip:
            is_dst_wl = self._is_ip_whitelisted(event.dest_ip)
            if is_dst_wl:
                return True

        if event.file_path:
            is_path_wl = self._is_path_whitelisted(event.file_path)
            if is_path_wl:
                return True

        return False

    def _is_process_whitelisted(self, name: str) -> bool:
        """Check if a process name is whitelisted.

        Args:
            name: Process name to check.

        Returns:
            True if whitelisted.
        """
        name_lower = name.lower()
        name_no_ext = name_lower.rsplit(".", 1)[0] if "." in name_lower else name_lower
        return name_lower in self._process_cache or name_no_ext in self._process_cache

    def _is_ip_whitelisted(self, ip_str: str) -> bool:
        """Check if an IP address is whitelisted.

        Args:
            ip_str: IP address string.

        Returns:
            True if whitelisted.
        """
        if ip_str in self._ip_cache:
            return True

        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        return any(ip in network for network in self._ip_ranges)

    def _is_path_whitelisted(self, path: str) -> bool:
        """Check if a file path is whitelisted.

        Args:
            path: File path to check.

        Returns:
            True if whitelisted.
        """
        return path.lower() in self._path_cache

    def add_entry(
        self,
        entry_type: str,
        value: str,
        reason: str,
        added_by: str = "user",
    ) -> None:
        """Add a new whitelist entry.

        Args:
            entry_type: Type (process/ip/hash/path).
            value: The value to whitelist.
            reason: Reason for whitelisting.
            added_by: Who added the entry.

        Raises:
            ValueError: If entry_type is invalid.
        """
        valid_types = {"process", "ip", "hash", "path"}
        if entry_type not in valid_types:
            raise ValueError(f"Invalid entry_type: {entry_type!r}. Must be one of {valid_types}")

        timestamp = datetime.now(timezone.utc).isoformat()
        self._db.upsert_whitelist(entry_type, value, reason, added_by, timestamp)

        if entry_type == "process":
            self._process_cache.add(value.lower())
        elif entry_type == "ip":
            self._ip_cache.add(value)
        elif entry_type == "hash":
            self._hash_cache.add(value.lower())
        elif entry_type == "path":
            self._path_cache.add(value.lower())

        logger.info("Whitelist entry added: %s=%s (by %s)", entry_type, value, added_by)
