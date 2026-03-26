"""Abstract base class for response actions."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ResponseResult:
    """Result of executing a response action.

    Attributes:
        success: Whether the action completed successfully.
        message: Human-readable result message.
        rollback_data: Data needed to undo this action.
        error: Error message if the action failed.
    """

    success: bool
    message: str
    rollback_data: dict[str, Any] | None = None
    error: str | None = None


class BaseResponse(ABC):
    """Abstract base class for all response actions.

    Each response must implement validate, execute, rollback,
    and describe methods.
    """

    @abstractmethod
    def validate(self) -> bool:
        """Check preconditions before execution.

        Returns:
            True if the action can be safely executed.
        """
        ...

    @abstractmethod
    def execute(self) -> ResponseResult:
        """Perform the response action.

        Must be idempotent where possible.

        Returns:
            ResponseResult with success status and rollback data.
        """
        ...

    @abstractmethod
    def rollback(self, rollback_data: dict[str, Any]) -> ResponseResult:
        """Undo the action using stored rollback data.

        Args:
            rollback_data: Data from the original execution.

        Returns:
            ResponseResult indicating rollback success.
        """
        ...

    @abstractmethod
    def describe(self) -> str:
        """Return a human-readable description of what this action will do.

        Returns:
            Description string.
        """
        ...
