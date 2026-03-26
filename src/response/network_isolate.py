"""Network adapter isolation for emergency containment."""

from __future__ import annotations

import logging
import subprocess
from src.core.subprocess_utils import run_silent
from typing import Any

from src.core.config import AppConfig
from src.response.base import BaseResponse, ResponseResult

logger = logging.getLogger(__name__)

NETSH_TIMEOUT = 15


class NetworkIsolate(BaseResponse):
    """Disable a network adapter to isolate the machine.

    This is a drastic action and should only be used in
    critical situations (active data exfiltration, etc.).

    Args:
        interface_name: Name of the network interface to disable.
        config: Application configuration.
    """

    def __init__(self, interface_name: str, config: AppConfig) -> None:
        if not interface_name:
            raise ValueError("interface_name must not be empty")
        self._interface = interface_name
        self._dry_run = config.response.dry_run

    def validate(self) -> bool:
        """Check that the interface exists.

        Returns:
            True if the interface exists.
        """
        try:
            result = run_silent(
                ["netsh", "interface", "show", "interface", self._interface],
                timeout=NETSH_TIMEOUT,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def execute(self) -> ResponseResult:
        """Disable the network interface.

        Returns:
            ResponseResult with rollback data.
        """
        if self._dry_run:
            msg = f"[DRY RUN] Would disable interface {self._interface}"
            return ResponseResult(
                success=True,
                message=msg,
                rollback_data={"interface": self._interface},
            )

        try:
            result = run_silent(
                ["netsh", "interface", "set", "interface",
                 self._interface, "admin=disable"],
                timeout=NETSH_TIMEOUT,
            )
            if result.returncode != 0:
                return ResponseResult(
                    success=False,
                    message=f"Failed to disable {self._interface}",
                    error=result.stderr.strip(),
                )
        except subprocess.TimeoutExpired:
            return ResponseResult(
                success=False,
                message="Interface disable timed out",
                error="Timeout",
            )

        msg = f"Network interface {self._interface} disabled"
        logger.warning(msg)
        return ResponseResult(
            success=True,
            message=msg,
            rollback_data={"interface": self._interface},
        )

    def rollback(self, rollback_data: dict[str, Any]) -> ResponseResult:
        """Re-enable the network interface.

        Args:
            rollback_data: Must contain 'interface' name.

        Returns:
            ResponseResult indicating success.
        """
        iface = rollback_data.get("interface", self._interface)

        if self._dry_run:
            return ResponseResult(
                success=True,
                message=f"[DRY RUN] Would re-enable interface {iface}",
            )

        try:
            result = run_silent(
                ["netsh", "interface", "set", "interface",
                 iface, "admin=enable"],
                timeout=NETSH_TIMEOUT,
            )
            if result.returncode != 0:
                return ResponseResult(
                    success=False,
                    message=f"Failed to re-enable {iface}",
                    error=result.stderr.strip(),
                )
        except subprocess.TimeoutExpired:
            return ResponseResult(
                success=False,
                message="Interface enable timed out",
                error="Timeout",
            )

        msg = f"Network interface {iface} re-enabled"
        logger.info(msg)
        return ResponseResult(success=True, message=msg)

    def describe(self) -> str:
        """Describe what this action will do."""
        prefix = "[DRY RUN] " if self._dry_run else ""
        return (
            f"{prefix}Disable network interface '{self._interface}' "
            f"to isolate this machine from the network"
        )
