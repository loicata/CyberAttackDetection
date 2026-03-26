"""Kill a malicious process by PID."""

from __future__ import annotations

import logging
import subprocess
from src.core.subprocess_utils import run_silent
from typing import Any

import psutil

from src.core.config import AppConfig
from src.core.exceptions import ResponseError
from src.response.base import BaseResponse, ResponseResult

logger = logging.getLogger(__name__)


class ProcessKill(BaseResponse):
    """Terminate a process by PID after capturing its state.

    Args:
        pid: Process ID to kill.
        config: Application configuration.
    """

    def __init__(self, pid: int, config: AppConfig) -> None:
        if not isinstance(pid, int) or pid <= 0:
            raise ValueError(f"PID must be a positive integer, got {pid!r}")
        self._pid = pid
        self._dry_run = config.response.dry_run
        self._process_info: dict[str, Any] | None = None

    def validate(self) -> bool:
        """Check that the process exists and can be accessed.

        Returns:
            True if the process exists.
        """
        try:
            proc = psutil.Process(self._pid)
            self._process_info = {
                "pid": proc.pid,
                "name": proc.name(),
                "exe": proc.exe(),
                "cmdline": proc.cmdline(),
                "username": proc.username(),
            }
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            logger.warning("Process %d not found or access denied", self._pid)
            return False

    def execute(self) -> ResponseResult:
        """Kill the process.

        Returns:
            ResponseResult. Note: process kill is NOT reversible.
        """
        if self._dry_run:
            msg = f"[DRY RUN] Would kill process {self._pid}"
            logger.info(msg)
            return ResponseResult(
                success=True,
                message=msg,
                rollback_data={"pid": self._pid, "info": self._process_info},
            )

        try:
            proc = psutil.Process(self._pid)
            proc_name = proc.name()
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        except psutil.NoSuchProcess:
            return ResponseResult(
                success=True,
                message=f"Process {self._pid} already terminated",
            )
        except psutil.AccessDenied:
            # Try taskkill as fallback (may have higher privileges)
            return self._taskkill_fallback()

        msg = f"Process {proc_name} (PID {self._pid}) terminated"
        logger.info(msg)
        return ResponseResult(
            success=True,
            message=msg,
            rollback_data={"pid": self._pid, "info": self._process_info,
                           "note": "Process kill is not reversible"},
        )

    def _taskkill_fallback(self) -> ResponseResult:
        """Try to kill the process using taskkill command.

        Returns:
            ResponseResult from taskkill attempt.
        """
        try:
            result = run_silent(["taskkill", "/F", "/PID", str(self._pid)], timeout=10)
            if result.returncode == 0:
                msg = f"Process {self._pid} killed via taskkill"
                logger.info(msg)
                return ResponseResult(success=True, message=msg)
            return ResponseResult(
                success=False,
                message=f"taskkill failed for PID {self._pid}",
                error=result.stderr.strip(),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return ResponseResult(
                success=False,
                message=f"Could not kill process {self._pid}",
                error=str(exc),
            )

    def rollback(self, rollback_data: dict[str, Any]) -> ResponseResult:
        """Process kill cannot be rolled back.

        Args:
            rollback_data: Contains original process info for reference.

        Returns:
            ResponseResult indicating rollback is not possible.
        """
        info = rollback_data.get("info", {})
        msg = (
            f"Process kill cannot be rolled back. "
            f"Original: {info.get('name', 'unknown')} "
            f"(PID {rollback_data.get('pid')}), "
            f"cmdline: {info.get('cmdline', 'N/A')}"
        )
        logger.warning(msg)
        return ResponseResult(success=False, message=msg, error="Not reversible")

    def describe(self) -> str:
        """Describe what this action will do."""
        prefix = "[DRY RUN] " if self._dry_run else ""
        name = self._process_info.get("name", "unknown") if self._process_info else "unknown"
        return f"{prefix}Terminate process {name} (PID {self._pid})"
