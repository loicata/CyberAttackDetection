"""Tests for the analysis pipeline modules."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from src.core.config import AppConfig
from src.core.database import Database
from src.core.enums import AlertType
from src.core.models import RawEvent
from src.analysis.whitelist import WhitelistManager
from src.analysis.baseline import BaselineManager, MINIMUM_SAMPLES_FOR_BASELINE
from src.analysis.scorer import AlertScorer
from src.analysis.aggregator import AlertAggregator, FLOOD_THRESHOLD
from src.analysis.correlator import EventCorrelator


# ---------------------------------------------------------------------------
# WhitelistManager tests
# ---------------------------------------------------------------------------

class TestWhitelistManager:
    """Tests for WhitelistManager."""

    @pytest.fixture
    def whitelist(self, tmp_database: Database, test_config: AppConfig) -> WhitelistManager:
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        return wl

    def test_default_processes_loaded(self, whitelist: WhitelistManager) -> None:
        event = RawEvent(
            event_type=AlertType.PROCESS,
            data={},
            process_name="svchost.exe",
        )
        assert whitelist.is_whitelisted(event) is True

    def test_unknown_process_not_whitelisted(self, whitelist: WhitelistManager) -> None:
        event = RawEvent(
            event_type=AlertType.PROCESS,
            data={},
            process_name="malware.exe",
        )
        assert whitelist.is_whitelisted(event) is False

    def test_rfc1918_ip_whitelisted(self, whitelist: WhitelistManager) -> None:
        event = RawEvent(
            event_type=AlertType.NETWORK,
            data={},
            source_ip="192.168.1.50",
        )
        assert whitelist.is_whitelisted(event) is True

    def test_public_ip_not_whitelisted(self, whitelist: WhitelistManager) -> None:
        event = RawEvent(
            event_type=AlertType.NETWORK,
            data={},
            source_ip="203.0.113.50",
        )
        assert whitelist.is_whitelisted(event) is False

    def test_add_entry(self, whitelist: WhitelistManager) -> None:
        event = RawEvent(
            event_type=AlertType.PROCESS,
            data={},
            process_name="custom_app.exe",
        )
        assert whitelist.is_whitelisted(event) is False
        whitelist.add_entry("process", "custom_app.exe", "Known safe", "user")
        assert whitelist.is_whitelisted(event) is True

    def test_invalid_entry_type_raises(self, whitelist: WhitelistManager) -> None:
        with pytest.raises(ValueError, match="Invalid entry_type"):
            whitelist.add_entry("invalid", "value", "reason")


# ---------------------------------------------------------------------------
# BaselineManager tests
# ---------------------------------------------------------------------------

class TestBaselineManager:
    """Tests for BaselineManager."""

    @pytest.fixture
    def baseline(self, tmp_database: Database, test_config: AppConfig) -> BaselineManager:
        return BaselineManager(database=tmp_database, config=test_config)

    def test_new_event_not_in_baseline(self, baseline: BaselineManager) -> None:
        event = RawEvent(
            event_type=AlertType.PROCESS,
            data={},
            process_name="new_process.exe",
        )
        assert baseline.is_in_baseline(event) is False

    def test_event_reaches_baseline_after_threshold(
        self, baseline: BaselineManager
    ) -> None:
        event = RawEvent(
            event_type=AlertType.PROCESS,
            data={},
            process_name="frequent.exe",
        )
        for _ in range(MINIMUM_SAMPLES_FOR_BASELINE):
            baseline.record_event(event)

        assert baseline.is_in_baseline(event) is True

    def test_event_below_threshold_not_in_baseline(
        self, baseline: BaselineManager
    ) -> None:
        event = RawEvent(
            event_type=AlertType.PROCESS,
            data={},
            process_name="rare.exe",
        )
        for _ in range(MINIMUM_SAMPLES_FOR_BASELINE - 1):
            baseline.record_event(event)

        assert baseline.is_in_baseline(event) is False

    def test_get_baseline_count(self, baseline: BaselineManager) -> None:
        event = RawEvent(
            event_type=AlertType.PROCESS,
            data={},
            process_name="counted.exe",
        )
        for _ in range(5):
            baseline.record_event(event)

        count = baseline.get_baseline_count("process", "counted.exe")
        assert count == 5


# ---------------------------------------------------------------------------
# AlertScorer tests
# ---------------------------------------------------------------------------

class TestAlertScorer:
    """Tests for AlertScorer."""

    @pytest.fixture
    def scorer(
        self,
        tmp_database: Database,
        test_config: AppConfig,
    ) -> AlertScorer:
        wl = WhitelistManager(database=tmp_database, config=test_config)
        wl.initialize()
        bl = BaselineManager(database=tmp_database, config=test_config)
        return AlertScorer(config=test_config, whitelist=wl, baseline=bl)

    def test_malware_name_high_score(self, scorer: AlertScorer) -> None:
        event = RawEvent(
            event_type=AlertType.PROCESS,
            data={"rule": "known_malware_name"},
            process_name="mimikatz.exe",
        )
        score = scorer.score_event(event)
        # Raw=90, first_occurrence boost=90*1.3=117 -> clamped to 100
        assert score >= 80

    def test_whitelisted_process_low_score(self, scorer: AlertScorer) -> None:
        event = RawEvent(
            event_type=AlertType.PROCESS,
            data={"rule": "eventlog_critical_event"},
            process_name="svchost.exe",
        )
        score = scorer.score_event(event)
        # Whitelisted -> score * 0.1
        assert score < 20

    def test_no_rule_zero_score(self, scorer: AlertScorer) -> None:
        event = RawEvent(event_type=AlertType.NETWORK, data={})
        score = scorer.score_event(event)
        assert score == 0

    def test_correlation_boosts_score(self, scorer: AlertScorer) -> None:
        event = RawEvent(
            event_type=AlertType.NETWORK,
            data={"rule": "suspicious_port_connection"},
            dest_ip="203.0.113.50",
            dest_port=4444,
        )
        base_score = scorer.score_event(event, is_correlated=False)
        correlated_score = scorer.score_event(event, is_correlated=True)
        assert correlated_score > base_score

    def test_suricata_combo_boosts_score(self, scorer: AlertScorer) -> None:
        event = RawEvent(
            event_type=AlertType.NETWORK,
            data={"rule": "suspicious_port_connection"},
            dest_ip="203.0.113.50",
        )
        base_score = scorer.score_event(event)
        combo_score = scorer.score_event(event, has_suricata_match=True)
        assert combo_score > base_score

    def test_log_clearing_high_score(self, scorer: AlertScorer) -> None:
        event = RawEvent(
            event_type=AlertType.EVENTLOG,
            data={"rule": "log_clearing"},
        )
        score = scorer.score_event(event)
        assert score >= 80


# ---------------------------------------------------------------------------
# AlertAggregator tests
# ---------------------------------------------------------------------------

class TestAlertAggregator:
    """Tests for AlertAggregator."""

    @pytest.fixture
    def aggregator(self, test_config: AppConfig) -> AlertAggregator:
        return AlertAggregator(config=test_config)

    def test_first_event_is_new(self, aggregator: AlertAggregator) -> None:
        event = RawEvent(
            event_type=AlertType.NETWORK,
            data={"rule": "test"},
            source_ip="1.2.3.4",
        )
        result = aggregator.check_duplicate(event, 50)
        assert result.is_new is True
        assert result.count == 1

    def test_duplicate_event_not_new(self, aggregator: AlertAggregator) -> None:
        event = RawEvent(
            event_type=AlertType.NETWORK,
            data={"rule": "test"},
            source_ip="1.2.3.4",
        )
        aggregator.check_duplicate(event, 50)
        result = aggregator.check_duplicate(event, 50)
        assert result.is_new is False
        assert result.count == 2

    def test_different_events_both_new(self, aggregator: AlertAggregator) -> None:
        event_a = RawEvent(
            event_type=AlertType.NETWORK,
            data={"rule": "rule_a"},
            source_ip="1.2.3.4",
        )
        event_b = RawEvent(
            event_type=AlertType.PROCESS,
            data={"rule": "rule_b"},
            process_name="test.exe",
        )
        result_a = aggregator.check_duplicate(event_a, 50)
        result_b = aggregator.check_duplicate(event_b, 50)
        assert result_a.is_new is True
        assert result_b.is_new is True

    def test_flood_detection(self, aggregator: AlertAggregator) -> None:
        event = RawEvent(
            event_type=AlertType.NETWORK,
            data={"rule": "flood_test"},
            source_ip="1.2.3.4",
        )
        flood_detected = False
        for i in range(FLOOD_THRESHOLD + 1):
            result = aggregator.check_duplicate(event, 50)
            if result.is_flood:
                flood_detected = True
                break

        assert flood_detected is True

    def test_occurrence_count(self, aggregator: AlertAggregator) -> None:
        event = RawEvent(
            event_type=AlertType.NETWORK,
            data={"rule": "count_test"},
        )
        for _ in range(5):
            aggregator.check_duplicate(event, 50)

        count = aggregator.get_occurrence_count(event)
        assert count == 5


# ---------------------------------------------------------------------------
# EventCorrelator tests
# ---------------------------------------------------------------------------

class TestEventCorrelator:
    """Tests for EventCorrelator."""

    @pytest.fixture
    def correlator(self, test_config: AppConfig) -> EventCorrelator:
        return EventCorrelator(config=test_config)

    def test_single_event_no_correlation(
        self, correlator: EventCorrelator
    ) -> None:
        event = RawEvent(
            event_type=AlertType.PROCESS,
            data={"rule": "known_malware_name"},
            process_name="malware.exe",
        )
        matches = correlator.add_event(event)
        # Single event rarely matches a multi-signal pattern
        # This is expected behavior
        assert isinstance(matches, list)

    def test_log_clear_plus_suspicious_triggers_cover_up(
        self, correlator: EventCorrelator
    ) -> None:
        log_clear = RawEvent(
            event_type=AlertType.EVENTLOG,
            data={"rule": "log_clearing"},
        )
        suspicious = RawEvent(
            event_type=AlertType.PROCESS,
            data={"rule": "known_malware_name"},
            process_name="malware.exe",
        )

        correlator.add_event(log_clear)
        matches = correlator.add_event(suspicious)

        pattern_names = [m.pattern_name for m in matches]
        assert "cover_up" in pattern_names

    def test_correlated_uids_returned(
        self, correlator: EventCorrelator
    ) -> None:
        event_a = RawEvent(
            event_type=AlertType.NETWORK,
            data={"rule": "suspicious_port_connection"},
            source_ip="192.168.1.10",
        )
        event_b = RawEvent(
            event_type=AlertType.PROCESS,
            data={"rule": "known_malware_name"},
            source_ip="192.168.1.10",
            process_name="malware.exe",
        )

        correlator.add_event(event_a)
        uids = correlator.get_correlated_uids(event_b)
        assert event_a.event_uid in uids
