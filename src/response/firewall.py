"""Block IP addresses via Windows Firewall (netsh)."""

from __future__ import annotations

import ipaddress
import logging
import subprocess
from src.core.subprocess_utils import run_silent
from typing import Any

from src.core.config import AppConfig
from src.core.exceptions import ResponseError
from src.response.base import BaseResponse, ResponseResult

logger = logging.getLogger(__name__)

NETSH_TIMEOUT_SECONDS = 30


class FirewallBlockIP(BaseResponse):
    """Block an IP address using Windows Firewall.

    Args:
        ip_address: IP address to block.
        config: Application configuration.
    """

    def __init__(self, ip_address: str, config: AppConfig) -> None:
        if not ip_address:
            raise ValueError("ip_address must not be empty")

        try:
            ipaddress.ip_address(ip_address)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {ip_address!r}") from exc

        self._ip = ip_address
        self._rule_name = f"{config.response.firewall_rule_prefix}{ip_address}"
        self._dry_run = config.response.dry_run

    def validate(self) -> bool:
        """Check that netsh is available and IP is valid.

        Returns:
            True if action can be executed.
        """
        try:
            result = run_silent(["netsh", "advfirewall", "show", "currentprofile"], timeout=10)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.error("netsh not available or timed out")
            return False

    def execute(self) -> ResponseResult:
        """Create a firewall rule to block the IP.

        Returns:
            ResponseResult with success status.
        """
        if self._dry_run:
            msg = f"[DRY RUN] Would block IP {self._ip} with rule {self._rule_name}"
            logger.info(msg)
            return ResponseResult(
                success=True,
                message=msg,
                rollback_data={"rule_name": self._rule_name, "ip": self._ip},
            )

        cmd_inbound = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={self._rule_name}_IN",
            "dir=in", "action=block",
            f"remoteip={self._ip}",
            "enable=yes",
        ]
        cmd_outbound = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={self._rule_name}_OUT",
            "dir=out", "action=block",
            f"remoteip={self._ip}",
            "enable=yes",
        ]

        try:
            for cmd in [cmd_inbound, cmd_outbound]:
                result = run_silent(cmd, timeout=NETSH_TIMEOUT_SECONDS)
                if result.returncode != 0:
                    return ResponseResult(
                        success=False,
                        message=f"Failed to add firewall rule",
                        error=result.stderr.strip(),
                    )
        except subprocess.TimeoutExpired:
            return ResponseResult(
                success=False,
                message="Firewall rule creation timed out",
                error="Timeout",
            )

        msg = f"Blocked IP {self._ip} (rules: {self._rule_name}_IN/OUT)"
        logger.info(msg)
        return ResponseResult(
            success=True,
            message=msg,
            rollback_data={"rule_name": self._rule_name, "ip": self._ip},
        )

    def rollback(self, rollback_data: dict[str, Any]) -> ResponseResult:
        """Remove the firewall block rules.

        Args:
            rollback_data: Must contain 'rule_name'.

        Returns:
            ResponseResult indicating rollback success.
        """
        rule_name = rollback_data.get("rule_name", self._rule_name)

        if self._dry_run:
            msg = f"[DRY RUN] Would remove firewall rules {rule_name}_IN/OUT"
            return ResponseResult(success=True, message=msg)

        errors: list[str] = []
        for suffix in ["_IN", "_OUT"]:
            try:
                result = run_silent(
                    ["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name={rule_name}{suffix}"],
                    timeout=NETSH_TIMEOUT_SECONDS,
                )
                if result.returncode != 0:
                    errors.append(f"{suffix}: {result.stderr.strip()}")
            except subprocess.TimeoutExpired:
                errors.append(f"{suffix}: timeout")

        if errors:
            return ResponseResult(
                success=False,
                message=f"Partial rollback for {rule_name}",
                error="; ".join(errors),
            )

        msg = f"Removed firewall rules {rule_name}_IN/OUT"
        logger.info(msg)
        return ResponseResult(success=True, message=msg)

    def describe(self) -> str:
        """Describe what this action will do."""
        prefix = "[DRY RUN] " if self._dry_run else ""
        return f"{prefix}Block all inbound and outbound traffic from/to {self._ip}"
