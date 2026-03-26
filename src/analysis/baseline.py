"""Behavioral baseline manager.

Builds and maintains statistical profiles of normal system behavior
to distinguish genuine threats from routine activity.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from src.core.config import AppConfig
from src.core.database import Database
from src.core.models import RawEvent

logger = logging.getLogger(__name__)

MINIMUM_SAMPLES_FOR_BASELINE = 10


class BaselineManager:
    """Manage behavioral baselines for anomaly detection.

    Tracks how frequently processes, network connections, and filesystem
    events occur to distinguish normal activity from anomalies.

    Args:
        database: Database instance for persistence.
        config: Application configuration.
    """

    def __init__(self, database: Database, config: AppConfig) -> None:
        if not isinstance(database, Database):
            raise TypeError(f"Expected Database, got {type(database).__name__}")
        self._db = database
        self._config = config
        self._cache: dict[tuple[str, str], dict[str, Any]] = {}

    def record_event(self, event: RawEvent) -> None:
        """Record an event to update the behavioral baseline.

        Args:
            event: The raw event to record.
        """
        entries = self._extract_baseline_keys(event)
        timestamp = datetime.now(timezone.utc).isoformat()

        for category, key in entries:
            profile = self._get_or_create_profile(category, key)
            profile["count"] = profile.get("count", 0) + 1
            profile["last_seen"] = timestamp

            self._cache[(category, key)] = profile
            self._db.upsert_baseline(
                category, key, json.dumps(profile), timestamp
            )

    def is_in_baseline(self, event: RawEvent) -> bool:
        """Check if an event matches established baseline behavior.

        An event is considered "in baseline" if similar events have
        been seen at least MINIMUM_SAMPLES_FOR_BASELINE times.

        Args:
            event: The raw event to check.

        Returns:
            True if the event matches normal behavior patterns.
        """
        entries = self._extract_baseline_keys(event)

        for category, key in entries:
            profile = self._get_profile(category, key)
            if profile is None:
                continue

            count = profile.get("count", 0)
            has_enough_samples = count >= MINIMUM_SAMPLES_FOR_BASELINE
            if has_enough_samples:
                return True

        return False

    def get_baseline_count(self, category: str, key: str) -> int:
        """Get the observation count for a baseline entry.

        Args:
            category: Baseline category.
            key: Entry key.

        Returns:
            Number of times this entry has been observed.
        """
        profile = self._get_profile(category, key)
        if profile is None:
            return 0
        return profile.get("count", 0)

    def _extract_baseline_keys(
        self, event: RawEvent
    ) -> list[tuple[str, str]]:
        """Extract category/key pairs from an event for baseline tracking.

        Args:
            event: The raw event.

        Returns:
            List of (category, key) tuples.
        """
        keys: list[tuple[str, str]] = []

        if event.process_name:
            keys.append(("process", event.process_name.lower()))

        if event.dest_ip:
            keys.append(("network", event.dest_ip))

        if event.file_path:
            keys.append(("filesystem", event.file_path.lower()))

        return keys

    def _get_profile(
        self, category: str, key: str
    ) -> dict[str, Any] | None:
        """Retrieve a baseline profile from cache or database.

        Args:
            category: Baseline category.
            key: Entry key.

        Returns:
            Profile dict or None if not found.
        """
        cache_key = (category, key)
        if cache_key in self._cache:
            return self._cache[cache_key]

        row = self._db.get_baseline(category, key)
        if row is None:
            return None

        try:
            profile = json.loads(row["value_json"])
        except (json.JSONDecodeError, KeyError):
            return None

        self._cache[cache_key] = profile
        return profile

    def _get_or_create_profile(
        self, category: str, key: str
    ) -> dict[str, Any]:
        """Get existing profile or create a new empty one.

        Args:
            category: Baseline category.
            key: Entry key.

        Returns:
            Profile dictionary.
        """
        profile = self._get_profile(category, key)
        if profile is None:
            profile = {"count": 0, "first_seen": datetime.now(timezone.utc).isoformat()}
        return profile
