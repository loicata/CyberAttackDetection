"""Tests for response modules."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from src.core.config import AppConfig
from src.core.database import Database
from src.core.enums import AlertSeverity, AlertType, ResponseStatus, ResponseType
from src.core.models import Alert, RawEvent, ResponseRecord
from src.response.base import ResponseResult
from src.response.firewall import FirewallBlockIP
from src.response.process_kill import ProcessKill
from src.response.quarantine import QuarantineFile
from src.response.network_isolate import NetworkIsolate
from src.response.rollback_manager import RollbackManager
from src.response.response_executor import ResponseExecutor


class TestFirewallBlockIP:
    """Tests for FirewallBlockIP."""

    def test_invalid_ip_raises(self, test_config: AppConfig) -> None:
        with pytest.raises(ValueError, match="Invalid IP"):
            FirewallBlockIP("not_an_ip", test_config)

    def test_empty_ip_raises(self, test_config: AppConfig) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            FirewallBlockIP("", test_config)

    def test_describe(self, test_config: AppConfig) -> None:
        action = FirewallBlockIP("1.2.3.4", test_config)
        desc = action.describe()
        assert "1.2.3.4" in desc
        assert "DRY RUN" in desc  # test_config has dry_run=True

    def test_dry_run_execute(self, test_config: AppConfig) -> None:
        action = FirewallBlockIP("1.2.3.4", test_config)
        result = action.execute()
        assert result.success is True
        assert "DRY RUN" in result.message
        assert result.rollback_data is not None

    def test_dry_run_rollback(self, test_config: AppConfig) -> None:
        action = FirewallBlockIP("1.2.3.4", test_config)
        result = action.rollback({"rule_name": "TEST_BLOCK_1.2.3.4", "ip": "1.2.3.4"})
        assert result.success is True

    @patch("subprocess.run")
    def test_validate_netsh_available(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        action = FirewallBlockIP("1.2.3.4", test_config)
        assert action.validate() is True


class TestProcessKill:
    """Tests for ProcessKill."""

    def test_invalid_pid_raises(self, test_config: AppConfig) -> None:
        with pytest.raises(ValueError, match="positive integer"):
            ProcessKill(-1, test_config)

    def test_describe(self, test_config: AppConfig) -> None:
        action = ProcessKill(1234, test_config)
        desc = action.describe()
        assert "1234" in desc

    def test_dry_run_execute(self, test_config: AppConfig) -> None:
        action = ProcessKill(1234, test_config)
        result = action.execute()
        assert result.success is True
        assert "DRY RUN" in result.message

    def test_rollback_not_reversible(self, test_config: AppConfig) -> None:
        action = ProcessKill(1234, test_config)
        result = action.rollback({"pid": 1234, "info": {"name": "test.exe"}})
        assert result.success is False
        assert "Not reversible" in result.error


class TestQuarantineFile:
    """Tests for QuarantineFile."""

    def test_empty_path_raises(self, test_config: AppConfig) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            QuarantineFile("", test_config)

    def test_describe(self, test_config: AppConfig) -> None:
        action = QuarantineFile(r"C:\test.exe", test_config)
        assert "test.exe" in action.describe()

    def test_dry_run_execute(self, test_config: AppConfig) -> None:
        action = QuarantineFile(r"C:\test.exe", test_config)
        result = action.execute()
        assert result.success is True
        assert "DRY RUN" in result.message

    def test_validate_nonexistent_file(self, test_config: AppConfig) -> None:
        action = QuarantineFile(r"C:\nonexistent_file_xyz.exe", test_config)
        assert action.validate() is False

    def test_validate_existing_file(
        self, test_config: AppConfig, tmp_path: Path
    ) -> None:
        test_file = tmp_path / "suspicious.exe"
        test_file.write_text("malware")
        action = QuarantineFile(str(test_file), test_config)
        assert action.validate() is True


class TestNetworkIsolate:
    """Tests for NetworkIsolate."""

    def test_empty_interface_raises(self, test_config: AppConfig) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            NetworkIsolate("", test_config)

    def test_describe(self, test_config: AppConfig) -> None:
        action = NetworkIsolate("Ethernet", test_config)
        assert "Ethernet" in action.describe()

    def test_dry_run_execute(self, test_config: AppConfig) -> None:
        action = NetworkIsolate("Ethernet", test_config)
        result = action.execute()
        assert result.success is True
        assert "DRY RUN" in result.message

    def test_dry_run_rollback(self, test_config: AppConfig) -> None:
        action = NetworkIsolate("Ethernet", test_config)
        result = action.rollback({"interface": "Ethernet"})
        assert result.success is True


class TestRollbackManager:
    """Tests for RollbackManager."""

    def test_record_action(
        self, tmp_database: Database, sample_alert: Alert
    ) -> None:
        tmp_database.insert_alert(sample_alert)
        mgr = RollbackManager(database=tmp_database)
        record = ResponseRecord(
            alert_uid=sample_alert.alert_uid,
            action_type=ResponseType.BLOCK_IP,
            parameters={"ip": "1.2.3.4"},
            rollback_data={"rule_name": "TEST"},
        )
        mgr.record_action(record)
        # Should not raise

    def test_update_status(
        self, tmp_database: Database, sample_alert: Alert
    ) -> None:
        tmp_database.insert_alert(sample_alert)
        mgr = RollbackManager(database=tmp_database)
        record = ResponseRecord(
            alert_uid=sample_alert.alert_uid,
            action_type=ResponseType.BLOCK_IP,
            parameters={"ip": "1.2.3.4"},
        )
        mgr.record_action(record)
        mgr.update_status(record.response_uid, ResponseStatus.EXECUTED)


class TestResponseExecutor:
    """Tests for ResponseExecutor."""

    @pytest.fixture
    def executor(
        self, test_config: AppConfig, tmp_database: Database, sample_alert: Alert
    ) -> ResponseExecutor:
        tmp_database.insert_alert(sample_alert)
        mgr = RollbackManager(database=tmp_database)
        return ResponseExecutor(config=test_config, rollback_manager=mgr)

    def test_get_available_actions(
        self, executor: ResponseExecutor, sample_alert: Alert
    ) -> None:
        actions = executor.get_available_actions(sample_alert)
        assert len(actions) >= 2  # At least isolate + report
        types = [a["type"] for a in actions]
        assert "report_only" in types

    def test_create_block_ip_action(
        self, executor: ResponseExecutor, sample_alert: Alert
    ) -> None:
        action = executor.create_action(
            ResponseType.BLOCK_IP, sample_alert, {"ip": "1.2.3.4"}
        )
        assert isinstance(action, FirewallBlockIP)

    def test_create_kill_process_action(
        self, executor: ResponseExecutor, sample_alert: Alert
    ) -> None:
        action = executor.create_action(
            ResponseType.KILL_PROCESS, sample_alert
        )
        assert isinstance(action, ProcessKill)

    def test_execute_dry_run(
        self, executor: ResponseExecutor, sample_alert: Alert
    ) -> None:
        result = executor.execute_action(
            ResponseType.BLOCK_IP,
            sample_alert,
            {"ip": "1.2.3.4"},
        )
        assert result.success is True
        assert "DRY RUN" in result.message
