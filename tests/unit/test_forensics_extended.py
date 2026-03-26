"""Extended tests for forensic modules to reach 80%+ coverage."""

from __future__ import annotations

import subprocess
from unittest.mock import patch, MagicMock

import pytest

from src.core.config import AppConfig
from src.forensics.registry_snapshot import (
    capture_registry_persistence,
    _query_registry_key,
    _parse_reg_output,
    capture_scheduled_tasks,
)
from src.forensics.snapshot import (
    _capture_system_info,
    _capture_processes,
    _capture_connections,
    _capture_single_process,
    capture_system_snapshot,
    capture_process_list,
    capture_network_connections,
    capture_process_details,
)
from src.core.exceptions import ForensicError


# ---------------------------------------------------------------------------
# Registry snapshot
# ---------------------------------------------------------------------------

class TestRegistrySnapshot:
    """Tests for registry_snapshot module."""

    @patch("subprocess.run")
    def test_query_registry_key_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
                "    SecurityHealth    REG_EXPAND_SZ    %ProgramFiles%\\Windows Defender\\MSASCuiL.exe\n"
                "    OneDrive    REG_SZ    C:\\Users\\user\\OneDrive\\OneDrive.exe\n"
            ),
        )
        entries = _query_registry_key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        assert len(entries) == 2
        assert entries[0]["name"] == "SecurityHealth"
        assert entries[1]["name"] == "OneDrive"

    def test_query_empty_key_raises(self) -> None:
        with pytest.raises(ForensicError, match="must not be empty"):
            _query_registry_key("")

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_query_no_reg_exe(self, mock: MagicMock) -> None:
        with pytest.raises(ForensicError, match="reg.exe not found"):
            _query_registry_key(r"HKLM\Test")

    @patch("subprocess.run")
    def test_query_timeout(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="reg", timeout=10)
        with pytest.raises(ForensicError, match="timed out"):
            _query_registry_key(r"HKLM\Test")

    @patch("subprocess.run")
    def test_query_nonzero_return(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stderr="ERROR: not found")
        with pytest.raises(ForensicError, match="failed"):
            _query_registry_key(r"HKLM\Nonexistent")

    def test_parse_reg_output_empty(self) -> None:
        result = _parse_reg_output("")
        assert result == []

    def test_parse_reg_output_skips_key_lines(self) -> None:
        output = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Test\n    Val1    REG_SZ    Data1\n"
        result = _parse_reg_output(output)
        assert len(result) == 1
        assert result[0]["name"] == "Val1"

    @patch("subprocess.run")
    def test_capture_registry_persistence(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="    TestVal    REG_SZ    TestData\n"
        )
        result = capture_registry_persistence()
        assert isinstance(result, dict)
        assert len(result) > 0

    @patch("subprocess.run")
    def test_capture_registry_access_denied(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stderr="Access denied")
        result = capture_registry_persistence()
        assert isinstance(result, dict)
        # All keys should have error entries
        for key, value in result.items():
            assert "error" in value

    @patch("subprocess.run")
    def test_capture_scheduled_tasks_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='"\\Microsoft\\UpdateTask","3/25/2026 9:00:00","Ready"\n'
                   '"\\MyTask","N/A","Running"\n',
        )
        tasks = capture_scheduled_tasks()
        assert len(tasks) == 2

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_capture_scheduled_tasks_no_schtasks(self, mock: MagicMock) -> None:
        result = capture_scheduled_tasks()
        assert result == []

    @patch("subprocess.run")
    def test_capture_scheduled_tasks_timeout(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="schtasks", timeout=30)
        result = capture_scheduled_tasks()
        assert result == []

    @patch("subprocess.run")
    def test_capture_scheduled_tasks_failure(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stderr="Error")
        result = capture_scheduled_tasks()
        assert result == []


# ---------------------------------------------------------------------------
# System snapshot
# ---------------------------------------------------------------------------

class TestSystemSnapshot:
    """Tests for snapshot.py functions."""

    def test_capture_system_info(self) -> None:
        info = _capture_system_info()
        assert "platform" in info
        assert "hostname" in info
        assert "cpu_count" in info
        assert info["cpu_count"] > 0

    def test_capture_processes_returns_list(self) -> None:
        procs = _capture_processes()
        assert isinstance(procs, list)
        assert len(procs) > 0
        first = procs[0]
        assert "pid" in first
        assert "name" in first

    def test_capture_connections_returns_list(self) -> None:
        conns = _capture_connections()
        assert isinstance(conns, list)
        # There should be at least some connections
        if conns:
            first = conns[0]
            assert "local_address" in first
            assert "status" in first

    def test_capture_single_process_current(self) -> None:
        import os
        pid = os.getpid()
        result = _capture_single_process(pid)
        assert result is not None
        assert result["pid"] == pid
        assert result["name"]  # Should have a name

    def test_capture_single_process_nonexistent(self) -> None:
        result = _capture_single_process(99999999)
        assert result is None

    @pytest.mark.asyncio
    async def test_capture_system_snapshot_async(self) -> None:
        snapshot = await capture_system_snapshot()
        assert "timestamp" in snapshot
        assert "system_info" in snapshot
        assert snapshot["process_count"] > 0

    @pytest.mark.asyncio
    async def test_capture_process_list_async(self) -> None:
        procs = await capture_process_list()
        assert isinstance(procs, list)
        assert len(procs) > 0

    @pytest.mark.asyncio
    async def test_capture_network_connections_async(self) -> None:
        conns = await capture_network_connections()
        assert isinstance(conns, list)

    @pytest.mark.asyncio
    async def test_capture_process_details_current(self) -> None:
        import os
        result = await capture_process_details(os.getpid())
        assert result is not None
        assert "loaded_modules" in result

    @pytest.mark.asyncio
    async def test_capture_process_details_nonexistent(self) -> None:
        result = await capture_process_details(99999999)
        assert result is None


# ---------------------------------------------------------------------------
# Console UI extended
# ---------------------------------------------------------------------------

class TestConsoleExtended:
    """Cover remaining console.py lines."""

    def test_print_intel_report_full(self) -> None:
        from src.ui.console import print_intel_report
        intel_data = {
            "ip_address": "203.0.113.50",
            "reverse_dns": ["host.example.com"],
            "whois_org": "Evil Corp",
            "whois_country": "RU",
            "geoip_country": "Russia",
            "geoip_city": "Moscow",
            "abuse_score": 85,
            "abuse_reports": 150,
            "virustotal_malicious": 12,
            "virustotal_total": 70,
        }
        print_intel_report(intel_data)  # Should not raise

    def test_print_intel_report_minimal(self) -> None:
        from src.ui.console import print_intel_report
        print_intel_report({"ip_address": "1.2.3.4"})

    def test_print_intel_report_low_scores(self) -> None:
        from src.ui.console import print_intel_report
        intel_data = {
            "ip_address": "8.8.8.8",
            "abuse_score": 5,
            "abuse_reports": 1,
            "virustotal_malicious": 0,
            "virustotal_total": 70,
        }
        print_intel_report(intel_data)

    def test_print_intel_report_medium_scores(self) -> None:
        from src.ui.console import print_intel_report
        intel_data = {
            "ip_address": "1.1.1.1",
            "abuse_score": 30,
            "abuse_reports": 10,
            "virustotal_malicious": 3,
            "virustotal_total": 70,
        }
        print_intel_report(intel_data)

    def test_get_user_choice_valid(self) -> None:
        from src.ui.console import get_user_choice
        with patch("src.ui.console.console") as mock_console:
            mock_console.input.return_value = "2"
            result = get_user_choice("Choose: ", 5)
            assert result == 2

    def test_get_user_choice_zero(self) -> None:
        from src.ui.console import get_user_choice
        with patch("src.ui.console.console") as mock_console:
            mock_console.input.return_value = "0"
            result = get_user_choice("Choose: ", 5)
            assert result == 0

    def test_get_user_choice_invalid_then_valid(self) -> None:
        from src.ui.console import get_user_choice
        with patch("src.ui.console.console") as mock_console:
            mock_console.input.side_effect = ["abc", "99", "3"]
            result = get_user_choice("Choose: ", 5)
            assert result == 3
