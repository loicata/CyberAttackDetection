"""Alert deduplication and aggregation.

Prevents alert fatigue by grouping identical or similar events
within a configurable time window.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from src.core.config import AppConfig
from src.core.models import Alert, RawEvent

logger = logging.getLogger(__name__)

FLOOD_THRESHOLD = 100


class AlertAggregator:
    """Deduplicate and aggregate similar alerts.

    Groups alerts with the same type, source, and target within
    a configurable time window.

    Args:
        config: Application configuration.
    """

    def __init__(self, config: AppConfig) -> None:
        self._window_seconds = config.analysis.aggregation_window_seconds
        self._active_groups: dict[str, _AlertGroup] = {}

    def check_duplicate(self, event: RawEvent, score: int) -> _AggregationResult:
        """Check if an event is a duplicate of an existing alert.

        Args:
            event: The raw event to check.
            score: The computed score for this event.

        Returns:
            AggregationResult indicating whether this is new, duplicate, or flood.
        """
        group_key = self._compute_group_key(event)
        now = time.monotonic()

        self._expire_old_groups(now)

        if group_key not in self._active_groups:
            self._active_groups[group_key] = _AlertGroup(
                first_seen=now,
                last_seen=now,
                count=1,
                max_score=score,
            )
            return _AggregationResult(is_new=True, is_flood=False, count=1)

        group = self._active_groups[group_key]
        group.count += 1
        group.last_seen = now
        group.max_score = max(group.max_score, score)

        is_flood = group.count >= FLOOD_THRESHOLD
        if is_flood and not group.flood_reported:
            group.flood_reported = True
            logger.warning(
                "Alert flood detected for group %s: %d events in window",
                group_key,
                group.count,
            )
            return _AggregationResult(
                is_new=False, is_flood=True, count=group.count
            )

        return _AggregationResult(
            is_new=False, is_flood=False, count=group.count
        )

    def get_occurrence_count(self, event: RawEvent) -> int:
        """Get the current occurrence count for an event's group.

        Args:
            event: The event to look up.

        Returns:
            Number of occurrences in the current window.
        """
        group_key = self._compute_group_key(event)
        group = self._active_groups.get(group_key)
        if group is None:
            return 0
        return group.count

    def _compute_group_key(self, event: RawEvent) -> str:
        """Compute a deduplication key for an event.

        Events with the same type, rule, source IP, dest IP,
        and process name are considered duplicates.

        Args:
            event: The raw event.

        Returns:
            String key for grouping.
        """
        rule = event.data.get("rule", "unknown")
        parts = [
            event.event_type.value,
            rule,
            event.source_ip or "",
            event.dest_ip or "",
            event.process_name or "",
        ]
        return "|".join(parts)

    def _expire_old_groups(self, now: float) -> None:
        """Remove groups that have exceeded the aggregation window.

        Args:
            now: Current monotonic time.
        """
        expired = [
            key
            for key, group in self._active_groups.items()
            if (now - group.last_seen) > self._window_seconds
        ]
        for key in expired:
            del self._active_groups[key]


class _AlertGroup:
    """Internal state for a group of deduplicated alerts.

    Attributes:
        first_seen: Monotonic time of first event.
        last_seen: Monotonic time of most recent event.
        count: Number of events in this group.
        max_score: Highest score seen in this group.
        flood_reported: Whether a flood alert was already generated.
    """

    __slots__ = ("first_seen", "last_seen", "count", "max_score", "flood_reported")

    def __init__(
        self,
        first_seen: float,
        last_seen: float,
        count: int,
        max_score: int,
    ) -> None:
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.count = count
        self.max_score = max_score
        self.flood_reported = False


class _AggregationResult:
    """Result of an aggregation check.

    Attributes:
        is_new: Whether this is the first event in its group.
        is_flood: Whether this triggers a flood alert.
        count: Current number of events in the group.
    """

    __slots__ = ("is_new", "is_flood", "count")

    def __init__(self, is_new: bool, is_flood: bool, count: int) -> None:
        self.is_new = is_new
        self.is_flood = is_flood
        self.count = count
