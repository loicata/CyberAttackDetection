"""Rollback manager for tracking and undoing response actions."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from src.core.database import Database
from src.core.enums import ResponseStatus, ResponseType
from src.core.models import ResponseRecord

logger = logging.getLogger(__name__)


class RollbackManager:
    """Track executed response actions and manage rollback.

    Args:
        database: Database instance for persistence.
    """

    def __init__(self, database: Database) -> None:
        self._db = database
        self._pending_rollbacks: list[ResponseRecord] = []

    def record_action(self, record: ResponseRecord) -> None:
        """Record an executed response action.

        Args:
            record: The response record to track.
        """
        self._db.insert_response(record)
        if record.rollback_data is not None:
            self._pending_rollbacks.append(record)
        logger.info(
            "Response recorded: %s for alert %s (status: %s)",
            record.action_type.value,
            record.alert_uid,
            record.status.value,
        )

    def update_status(
        self,
        response_uid: str,
        status: ResponseStatus,
        rollback_data: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> None:
        """Update the status of a response action.

        Args:
            response_uid: UID of the response.
            status: New status.
            rollback_data: Updated rollback data if applicable.
            error_message: Error message if applicable.
        """
        now = datetime.now(timezone.utc).isoformat()
        executed_at = now if status == ResponseStatus.EXECUTED else None
        rolled_back_at = now if status == ResponseStatus.ROLLED_BACK else None

        self._db.update_response_status(
            response_uid=response_uid,
            status=status.value,
            executed_at=executed_at,
            rolled_back_at=rolled_back_at,
            rollback_json=json.dumps(rollback_data) if rollback_data else None,
            error_message=error_message,
        )

    def get_rollback_candidates(self, alert_uid: str) -> list[ResponseRecord]:
        """Get response actions that can be rolled back for an alert.

        Args:
            alert_uid: UID of the alert.

        Returns:
            List of rollback-eligible ResponseRecords.
        """
        return [
            r for r in self._pending_rollbacks
            if r.alert_uid == alert_uid
            and r.status == ResponseStatus.EXECUTED
            and r.rollback_data is not None
        ]
