"""Alert scoring engine.

Assigns a confidence score (0-100) to each raw event based on
weighted rules and contextual modifiers.
"""

from __future__ import annotations

import logging
from typing import Any

from src.core.config import AppConfig
from src.core.models import RawEvent
from src.analysis.baseline import BaselineManager
from src.analysis.whitelist import WhitelistManager

logger = logging.getLogger(__name__)

# Contextual score multipliers
WHITELIST_MULTIPLIER = 0.1
BASELINE_MULTIPLIER = 0.7
FIRST_OCCURRENCE_MULTIPLIER = 1.3
CORRELATION_MULTIPLIER = 1.5
SURICATA_LOCAL_COMBO_MULTIPLIER = 1.8
RFC1918_MULTIPLIER = 0.6


class AlertScorer:
    """Score raw events to determine threat severity.

    Uses a two-phase approach:
    1. Raw score = max weight among triggered rules
    2. Contextual adjustment via multipliers

    Args:
        config: Application configuration.
        whitelist: Whitelist manager.
        baseline: Baseline manager.
    """

    def __init__(
        self,
        config: AppConfig,
        whitelist: WhitelistManager,
        baseline: BaselineManager,
    ) -> None:
        self._config = config
        self._whitelist = whitelist
        self._baseline = baseline
        self._weights = config.analysis.scoring_weights

    def score_event(
        self,
        event: RawEvent,
        is_correlated: bool = False,
        has_suricata_match: bool = False,
    ) -> int:
        """Calculate a confidence score for a raw event.

        Args:
            event: The raw event to score.
            is_correlated: Whether this event is correlated with others.
            has_suricata_match: Whether Suricata also flagged this activity.

        Returns:
            Integer score clamped to 0-100.
        """
        raw_score = self._calculate_raw_score(event)
        if raw_score == 0:
            return 0

        adjusted = self._apply_modifiers(
            raw_score, event, is_correlated, has_suricata_match
        )

        final_score = max(0, min(100, int(adjusted)))

        # Cap Suricata alerts: their severity should respect the original
        # Suricata classification. Medium alerts should not escalate to CRITICAL.
        from src.core.enums import AlertType
        if event.event_type == AlertType.SURICATA:
            suricata_severity = event.data.get("severity", 3)
            if suricata_severity >= 3:  # Low in Suricata
                final_score = min(final_score, 49)   # Cap at MEDIUM max
            elif suricata_severity == 2:  # Medium in Suricata
                final_score = min(final_score, 69)   # Cap at HIGH max
            # severity 1 (High in Suricata) → no cap, can be CRITICAL
        logger.debug(
            "Scored event %s: raw=%d, adjusted=%d (rule=%s)",
            event.event_uid,
            raw_score,
            final_score,
            event.data.get("rule", "unknown"),
        )
        return final_score

    def _calculate_raw_score(self, event: RawEvent) -> int:
        """Calculate raw score as the max weight of triggered rules.

        Args:
            event: The raw event.

        Returns:
            Raw score (0-100).
        """
        rule = event.data.get("rule")
        if not rule:
            return 0

        weight = self._weights.get(rule, 0)
        return weight

    def _apply_modifiers(
        self,
        raw_score: int,
        event: RawEvent,
        is_correlated: bool,
        has_suricata_match: bool,
    ) -> float:
        """Apply contextual multipliers to the raw score.

        Args:
            raw_score: The base score before modifiers.
            event: The raw event.
            is_correlated: Whether correlated with other events.
            has_suricata_match: Whether Suricata also flagged this.

        Returns:
            Adjusted score as float.
        """
        score = float(raw_score)

        # Suricata alerts bypass reduction modifiers — Suricata already
        # performed deep packet inspection, so whitelist/baseline/RFC1918
        # reductions would incorrectly suppress confirmed IDS alerts.
        from src.core.enums import AlertType

        is_suricata_event = event.event_type == AlertType.SURICATA

        # Reduction modifiers (skipped for Suricata alerts)
        is_whitelisted = False
        is_in_baseline = False
        if not is_suricata_event:
            is_whitelisted = self._whitelist.is_whitelisted(event)
            if is_whitelisted:
                score *= WHITELIST_MULTIPLIER
                logger.debug("Whitelist modifier applied: x%.1f", WHITELIST_MULTIPLIER)

            is_in_baseline = self._baseline.is_in_baseline(event)
            if is_in_baseline:
                score *= BASELINE_MULTIPLIER
                logger.debug("Baseline modifier applied: x%.1f", BASELINE_MULTIPLIER)

            is_rfc1918_source = self._is_rfc1918(event.source_ip)
            is_rfc1918_dest = self._is_rfc1918(event.dest_ip)
            if is_rfc1918_source and is_rfc1918_dest:
                score *= RFC1918_MULTIPLIER
                logger.debug("RFC1918 modifier applied: x%.1f", RFC1918_MULTIPLIER)

        # Boost modifiers
        is_first_occurrence = not is_in_baseline
        if is_first_occurrence and not is_whitelisted:
            score *= FIRST_OCCURRENCE_MULTIPLIER
            logger.debug(
                "First occurrence modifier applied: x%.1f",
                FIRST_OCCURRENCE_MULTIPLIER,
            )

        if is_correlated:
            score *= CORRELATION_MULTIPLIER
            logger.debug(
                "Correlation modifier applied: x%.1f",
                CORRELATION_MULTIPLIER,
            )

        if has_suricata_match:
            score *= SURICATA_LOCAL_COMBO_MULTIPLIER
            logger.debug(
                "Suricata combo modifier applied: x%.1f",
                SURICATA_LOCAL_COMBO_MULTIPLIER,
            )

        return score

    @staticmethod
    def _is_rfc1918(ip_str: str | None) -> bool:
        """Check if an IP address is in RFC1918 private range.

        Args:
            ip_str: IP address string or None.

        Returns:
            True if the IP is a private RFC1918 address.
        """
        if not ip_str:
            return False

        import ipaddress

        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False
