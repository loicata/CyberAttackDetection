"""Orchestrate response action execution and rollback."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from src.core.config import AppConfig
from src.core.enums import ResponseStatus, ResponseType
from src.core.models import Alert, ResponseRecord
from src.response.base import BaseResponse, ResponseResult
from src.response.firewall import FirewallBlockIP
from src.response.process_kill import ProcessKill
from src.response.quarantine import QuarantineFile
from src.response.network_isolate import NetworkIsolate
from src.response.rollback_manager import RollbackManager

logger = logging.getLogger(__name__)


class ResponseExecutor:
    """Execute and manage response actions for alerts.

    Args:
        config: Application configuration.
        rollback_manager: Rollback manager for tracking actions.
    """

    def __init__(
        self,
        config: AppConfig,
        rollback_manager: RollbackManager,
    ) -> None:
        self._config = config
        self._rollback_mgr = rollback_manager

    def create_action(
        self,
        response_type: ResponseType,
        alert: Alert,
        parameters: dict[str, Any] | None = None,
    ) -> BaseResponse:
        """Create a response action instance.

        Args:
            response_type: Type of response action.
            alert: The alert being responded to.
            parameters: Additional action-specific parameters.

        Returns:
            Configured BaseResponse instance.

        Raises:
            ValueError: If response_type is unsupported.
        """
        params = parameters or {}

        if response_type == ResponseType.BLOCK_IP:
            ip = params.get("ip") or alert.source_ip or alert.dest_ip
            if not ip:
                raise ValueError("No IP address available for firewall block")
            return FirewallBlockIP(ip_address=ip, config=self._config)

        if response_type == ResponseType.KILL_PROCESS:
            pid = params.get("pid") or alert.process_pid
            if not pid:
                raise ValueError("No PID available for process kill")
            return ProcessKill(pid=pid, config=self._config)

        if response_type == ResponseType.QUARANTINE_FILE:
            path = params.get("file_path") or alert.file_path
            if not path:
                raise ValueError("No file path available for quarantine")
            return QuarantineFile(file_path=path, config=self._config)

        if response_type == ResponseType.ISOLATE_NETWORK:
            iface = params.get("interface", "Ethernet")
            return NetworkIsolate(interface_name=iface, config=self._config)

        raise ValueError(f"Unsupported response type: {response_type}")

    def execute_action(
        self,
        response_type: ResponseType,
        alert: Alert,
        parameters: dict[str, Any] | None = None,
    ) -> ResponseResult:
        """Execute a response action with full lifecycle tracking.

        Args:
            response_type: Type of response to execute.
            alert: The alert being responded to.
            parameters: Additional action-specific parameters.

        Returns:
            ResponseResult with execution outcome.
        """
        action = self.create_action(response_type, alert, parameters)

        record = ResponseRecord(
            alert_uid=alert.alert_uid,
            action_type=response_type,
            parameters=parameters or {},
        )

        logger.info("Executing response: %s", action.describe())

        is_valid = action.validate()
        if not is_valid:
            record.status = ResponseStatus.FAILED
            record.error_message = "Validation failed"
            self._rollback_mgr.record_action(record)
            return ResponseResult(
                success=False,
                message=f"Validation failed for {response_type.value}",
                error="Preconditions not met",
            )

        result = action.execute()

        if result.success:
            record.status = ResponseStatus.EXECUTED
            record.executed_at = datetime.now(timezone.utc).isoformat()
            record.rollback_data = result.rollback_data
        else:
            record.status = ResponseStatus.FAILED
            record.error_message = result.error

        self._rollback_mgr.record_action(record)
        self._rollback_mgr.update_status(
            record.response_uid,
            record.status,
            rollback_data=result.rollback_data,
            error_message=result.error,
        )

        return result

    def get_available_actions(self, alert: Alert) -> list[dict[str, str]]:
        """Get list of available response actions for an alert.

        Args:
            alert: The alert to get actions for.

        Returns:
            List of action descriptions with type and description.
        """
        actions: list[dict[str, str]] = []

        has_ip = alert.source_ip or alert.dest_ip
        if has_ip:
            ip = alert.source_ip or alert.dest_ip
            actions.append({
                "type": ResponseType.BLOCK_IP.value,
                "description": f"Block IP {ip} via Windows Firewall",
            })

        if alert.process_pid:
            actions.append({
                "type": ResponseType.KILL_PROCESS.value,
                "description": f"Kill process {alert.process_name} (PID {alert.process_pid})",
            })

        if alert.file_path:
            actions.append({
                "type": ResponseType.QUARANTINE_FILE.value,
                "description": f"Quarantine file {alert.file_path}",
            })

        actions.append({
            "type": ResponseType.ISOLATE_NETWORK.value,
            "description": "Disable network adapter (emergency isolation)",
        })

        actions.append({
            "type": ResponseType.REPORT_ONLY.value,
            "description": "Generate forensic report only (no action)",
        })

        return actions
