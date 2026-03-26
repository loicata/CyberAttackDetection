"""Extended tests for response modules to reach 80%+ coverage."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from src.core.config import AppConfig
from src.core.database import Database
from src.core.enums import AlertSeverity, AlertType, ResponseType
from src.core.models import Alert, RawEvent
from src.response.firewall import FirewallBlockIP
from src.response.process_kill import ProcessKill
from src.response.quarantine import QuarantineFile
from src.response.network_isolate import NetworkIsolate
from src.response.response_executor import ResponseExecutor
from src.response.rollback_manager import RollbackManager


def _make_live_config(test_config: AppConfig) -> AppConfig:
    """Create config with dry_run=False for testing real execution paths."""
    from dataclasses import replace
    from src.core.config import ResponseConfig
    live_response = replace(test_config.response, dry_run=False)
    return replace(test_config, response=live_response)


# ---------------------------------------------------------------------------
# Firewall extended
# ---------------------------------------------------------------------------

class TestFirewallExtended:
    """Test firewall with mocked subprocess for real execution paths."""

    @patch("subprocess.run")
    def test_execute_success(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        action = FirewallBlockIP("203.0.113.50", cfg)
        result = action.execute()
        assert result.success is True
        assert result.rollback_data is not None
        assert mock_run.call_count == 2  # inbound + outbound

    @patch("subprocess.run")
    def test_execute_failure(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_run.return_value = MagicMock(returncode=1, stderr="Access denied")
        action = FirewallBlockIP("203.0.113.50", cfg)
        result = action.execute()
        assert result.success is False

    @patch("subprocess.run")
    def test_execute_timeout(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="netsh", timeout=30)
        action = FirewallBlockIP("203.0.113.50", cfg)
        result = action.execute()
        assert result.success is False

    @patch("subprocess.run")
    def test_rollback_success(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_run.return_value = MagicMock(returncode=0)
        action = FirewallBlockIP("203.0.113.50", cfg)
        result = action.rollback({"rule_name": "CAD_BLOCK_203.0.113.50", "ip": "203.0.113.50"})
        assert result.success is True

    @patch("subprocess.run")
    def test_rollback_partial_failure(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_run.return_value = MagicMock(returncode=1, stderr="Not found")
        action = FirewallBlockIP("203.0.113.50", cfg)
        result = action.rollback({"rule_name": "CAD_BLOCK_203.0.113.50"})
        assert result.success is False

    @patch("subprocess.run")
    def test_rollback_timeout(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="netsh", timeout=30)
        action = FirewallBlockIP("203.0.113.50", cfg)
        result = action.rollback({"rule_name": "CAD_BLOCK_203.0.113.50"})
        assert result.success is False

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_validate_no_netsh(self, mock: MagicMock, test_config: AppConfig) -> None:
        action = FirewallBlockIP("1.2.3.4", test_config)
        assert action.validate() is False

    @patch("subprocess.run")
    def test_validate_timeout(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="netsh", timeout=10)
        action = FirewallBlockIP("1.2.3.4", test_config)
        assert action.validate() is False


# ---------------------------------------------------------------------------
# ProcessKill extended
# ---------------------------------------------------------------------------

class TestProcessKillExtended:
    """Test process kill with mocked psutil."""

    @patch("psutil.Process")
    def test_validate_success(self, mock_proc_cls: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_proc = MagicMock()
        mock_proc.name.return_value = "evil.exe"
        mock_proc.exe.return_value = r"C:\Temp\evil.exe"
        mock_proc.cmdline.return_value = ["evil.exe", "--flag"]
        mock_proc.username.return_value = "USER\\admin"
        mock_proc_cls.return_value = mock_proc

        action = ProcessKill(9999, cfg)
        assert action.validate() is True
        assert action._process_info["name"] == "evil.exe"

    @patch("psutil.Process")
    def test_validate_no_such_process(self, mock_proc_cls: MagicMock, test_config: AppConfig) -> None:
        import psutil
        mock_proc_cls.side_effect = psutil.NoSuchProcess(9999)
        action = ProcessKill(9999, test_config)
        assert action.validate() is False

    @patch("psutil.Process")
    def test_execute_success(self, mock_proc_cls: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_proc = MagicMock()
        mock_proc.name.return_value = "evil.exe"
        mock_proc.terminate.return_value = None
        mock_proc.wait.return_value = None
        mock_proc_cls.return_value = mock_proc

        action = ProcessKill(9999, cfg)
        action._process_info = {"name": "evil.exe", "exe": "", "cmdline": [], "username": ""}
        result = action.execute()
        assert result.success is True
        mock_proc.terminate.assert_called_once()

    @patch("psutil.Process")
    def test_execute_no_such_process(self, mock_proc_cls: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        import psutil
        mock_proc_cls.side_effect = psutil.NoSuchProcess(9999)
        action = ProcessKill(9999, cfg)
        result = action.execute()
        assert result.success is True
        assert "already terminated" in result.message

    @patch("psutil.Process")
    def test_execute_access_denied_fallback(self, mock_proc_cls: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        import psutil
        mock_proc_cls.side_effect = psutil.AccessDenied(9999)
        action = ProcessKill(9999, cfg)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = action.execute()
            assert result.success is True

    @patch("psutil.Process")
    def test_execute_terminate_timeout_then_kill(
        self, mock_proc_cls: MagicMock, test_config: AppConfig
    ) -> None:
        cfg = _make_live_config(test_config)
        import psutil
        mock_proc = MagicMock()
        mock_proc.name.return_value = "stubborn.exe"
        mock_proc.terminate.return_value = None
        mock_proc.wait.side_effect = [psutil.TimeoutExpired(5), None]
        mock_proc.kill.return_value = None
        mock_proc_cls.return_value = mock_proc

        action = ProcessKill(9999, cfg)
        action._process_info = {"name": "stubborn.exe"}
        result = action.execute()
        assert result.success is True
        mock_proc.kill.assert_called_once()

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_taskkill_fallback_not_found(self, mock: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        action = ProcessKill(9999, cfg)
        result = action._taskkill_fallback()
        assert result.success is False

    @patch("subprocess.run")
    def test_taskkill_fallback_failure(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_run.return_value = MagicMock(returncode=1, stderr="not found")
        action = ProcessKill(9999, cfg)
        result = action._taskkill_fallback()
        assert result.success is False


# ---------------------------------------------------------------------------
# Quarantine extended
# ---------------------------------------------------------------------------

class TestQuarantineExtended:
    """Test quarantine with real file operations."""

    def test_execute_real_file(self, test_config: AppConfig, tmp_path: Path) -> None:
        cfg = _make_live_config(test_config)
        test_file = tmp_path / "malware.exe"
        test_file.write_text("MZ_fake_malware")

        action = QuarantineFile(str(test_file), cfg)
        result = action.execute()
        assert result.success is True
        assert not test_file.exists()  # Original moved
        assert result.rollback_data is not None
        assert "quarantine_path" in result.rollback_data

    def test_execute_and_rollback(self, test_config: AppConfig, tmp_path: Path) -> None:
        cfg = _make_live_config(test_config)
        test_file = tmp_path / "suspicious.dll"
        test_file.write_text("suspicious_content")

        action = QuarantineFile(str(test_file), cfg)
        exec_result = action.execute()
        assert exec_result.success is True
        assert not test_file.exists()

        rollback_result = action.rollback(exec_result.rollback_data)
        assert rollback_result.success is True
        assert test_file.exists()
        assert test_file.read_text() == "suspicious_content"

    def test_rollback_missing_data(self, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        action = QuarantineFile(r"C:\fake.exe", cfg)
        result = action.rollback({})
        assert result.success is False

    def test_rollback_missing_quarantined_file(self, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        action = QuarantineFile(r"C:\fake.exe", cfg)
        result = action.rollback({
            "original_path": r"C:\fake.exe",
            "quarantine_path": r"C:\nonexistent\quarantined.exe",
        })
        assert result.success is False


# ---------------------------------------------------------------------------
# NetworkIsolate extended
# ---------------------------------------------------------------------------

class TestNetworkIsolateExtended:
    """Test network isolation with mocked subprocess."""

    @patch("subprocess.run")
    def test_validate_success(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        action = NetworkIsolate("Wi-Fi", test_config)
        assert action.validate() is True

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_validate_no_netsh(self, mock: MagicMock, test_config: AppConfig) -> None:
        action = NetworkIsolate("Wi-Fi", test_config)
        assert action.validate() is False

    @patch("subprocess.run")
    def test_execute_success(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_run.return_value = MagicMock(returncode=0)
        action = NetworkIsolate("Ethernet", cfg)
        result = action.execute()
        assert result.success is True

    @patch("subprocess.run")
    def test_execute_failure(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_run.return_value = MagicMock(returncode=1, stderr="The interface does not exist")
        action = NetworkIsolate("FakeAdapter", cfg)
        result = action.execute()
        assert result.success is False

    @patch("subprocess.run")
    def test_execute_timeout(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="netsh", timeout=15)
        action = NetworkIsolate("Ethernet", cfg)
        result = action.execute()
        assert result.success is False

    @patch("subprocess.run")
    def test_rollback_success(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_run.return_value = MagicMock(returncode=0)
        action = NetworkIsolate("Ethernet", cfg)
        result = action.rollback({"interface": "Ethernet"})
        assert result.success is True

    @patch("subprocess.run")
    def test_rollback_failure(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_run.return_value = MagicMock(returncode=1, stderr="Failed")
        action = NetworkIsolate("Ethernet", cfg)
        result = action.rollback({"interface": "Ethernet"})
        assert result.success is False

    @patch("subprocess.run")
    def test_rollback_timeout(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        cfg = _make_live_config(test_config)
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="netsh", timeout=15)
        action = NetworkIsolate("Ethernet", cfg)
        result = action.rollback({"interface": "Ethernet"})
        assert result.success is False

    @patch("subprocess.run")
    def test_validate_timeout(self, mock_run: MagicMock, test_config: AppConfig) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="netsh", timeout=15)
        action = NetworkIsolate("Ethernet", test_config)
        assert action.validate() is False


# ---------------------------------------------------------------------------
# ResponseExecutor extended
# ---------------------------------------------------------------------------

class TestResponseExecutorExtended:
    """Extended tests for ResponseExecutor."""

    @pytest.fixture
    def executor(
        self, test_config: AppConfig, tmp_database: Database, sample_alert: Alert
    ) -> ResponseExecutor:
        tmp_database.insert_alert(sample_alert)
        mgr = RollbackManager(database=tmp_database)
        return ResponseExecutor(config=test_config, rollback_manager=mgr)

    def test_create_quarantine_action(
        self, executor: ResponseExecutor, sample_alert: Alert
    ) -> None:
        sample_alert.file_path = r"C:\test.exe"
        action = executor.create_action(ResponseType.QUARANTINE_FILE, sample_alert)
        assert isinstance(action, QuarantineFile)

    def test_create_isolate_action(
        self, executor: ResponseExecutor, sample_alert: Alert
    ) -> None:
        action = executor.create_action(
            ResponseType.ISOLATE_NETWORK, sample_alert, {"interface": "Wi-Fi"}
        )
        assert isinstance(action, NetworkIsolate)

    def test_create_unsupported_raises(
        self, executor: ResponseExecutor, sample_alert: Alert
    ) -> None:
        with pytest.raises(ValueError, match="Unsupported"):
            executor.create_action(ResponseType.REPORT_ONLY, sample_alert)

    def test_create_block_no_ip_raises(
        self, executor: ResponseExecutor
    ) -> None:
        raw = RawEvent(event_type=AlertType.FILESYSTEM, data={})
        alert = Alert(
            alert_type=AlertType.FILESYSTEM,
            severity=AlertSeverity.HIGH,
            score=70,
            title="Test",
            description="Test",
            raw_event=raw,
        )
        with pytest.raises(ValueError, match="No IP"):
            executor.create_action(ResponseType.BLOCK_IP, alert)

    def test_create_kill_no_pid_raises(
        self, executor: ResponseExecutor
    ) -> None:
        raw = RawEvent(event_type=AlertType.FILESYSTEM, data={})
        alert = Alert(
            alert_type=AlertType.FILESYSTEM,
            severity=AlertSeverity.HIGH,
            score=70,
            title="Test",
            description="Test",
            raw_event=raw,
        )
        with pytest.raises(ValueError, match="No PID"):
            executor.create_action(ResponseType.KILL_PROCESS, alert)

    def test_execute_validation_failure(
        self, executor: ResponseExecutor, sample_alert: Alert
    ) -> None:
        sample_alert.file_path = r"C:\nonexistent_file_xyz.exe"
        result = executor.execute_action(
            ResponseType.QUARANTINE_FILE, sample_alert,
        )
        assert result.success is False
        assert "Validation failed" in result.message

    def test_get_actions_file_path(
        self, executor: ResponseExecutor, sample_alert: Alert
    ) -> None:
        sample_alert.file_path = r"C:\suspicious.exe"
        actions = executor.get_available_actions(sample_alert)
        types = [a["type"] for a in actions]
        assert "quarantine_file" in types
