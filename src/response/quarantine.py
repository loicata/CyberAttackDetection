"""Move suspicious files to quarantine directory."""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any

from src.core.config import AppConfig
from src.core.exceptions import ResponseError
from src.forensics.file_hasher import compute_sha256
from src.response.base import BaseResponse, ResponseResult

logger = logging.getLogger(__name__)


class QuarantineFile(BaseResponse):
    """Move a suspicious file to quarantine.

    The file is moved to the quarantine directory and renamed
    with a .quarantined extension to prevent accidental execution.

    Args:
        file_path: Path to the file to quarantine.
        config: Application configuration.
    """

    def __init__(self, file_path: str, config: AppConfig) -> None:
        if not file_path:
            raise ValueError("file_path must not be empty")
        self._file_path = Path(file_path)
        self._quarantine_dir = Path(config.forensics.quarantine_dir)
        self._dry_run = config.response.dry_run

    def validate(self) -> bool:
        """Check that the file exists and quarantine dir is writable.

        Returns:
            True if the action can proceed.
        """
        if not self._file_path.exists():
            logger.warning("File not found: %s", self._file_path)
            return False

        self._quarantine_dir.mkdir(parents=True, exist_ok=True)
        return True

    def execute(self) -> ResponseResult:
        """Move the file to quarantine.

        Returns:
            ResponseResult with rollback data containing original path.
        """
        if self._dry_run:
            msg = f"[DRY RUN] Would quarantine {self._file_path}"
            return ResponseResult(
                success=True,
                message=msg,
                rollback_data={"original_path": str(self._file_path)},
            )

        try:
            file_hash = compute_sha256(self._file_path)
        except Exception:
            file_hash = "unknown"

        quarantine_subdir = self._quarantine_dir / file_hash[:16]
        quarantine_subdir.mkdir(parents=True, exist_ok=True)
        dest = quarantine_subdir / (self._file_path.name + ".quarantined")

        try:
            shutil.move(str(self._file_path), str(dest))
        except OSError as exc:
            return ResponseResult(
                success=False,
                message=f"Failed to quarantine {self._file_path}",
                error=str(exc),
            )

        msg = f"Quarantined {self._file_path} -> {dest}"
        logger.info(msg)
        return ResponseResult(
            success=True,
            message=msg,
            rollback_data={
                "original_path": str(self._file_path),
                "quarantine_path": str(dest),
                "file_hash": file_hash,
            },
        )

    def rollback(self, rollback_data: dict[str, Any]) -> ResponseResult:
        """Restore the file from quarantine to its original location.

        Args:
            rollback_data: Must contain original_path and quarantine_path.

        Returns:
            ResponseResult indicating success.
        """
        original = rollback_data.get("original_path")
        quarantined = rollback_data.get("quarantine_path")

        if not original or not quarantined:
            return ResponseResult(
                success=False,
                message="Missing rollback data",
                error="original_path and quarantine_path required",
            )

        if self._dry_run:
            msg = f"[DRY RUN] Would restore {quarantined} -> {original}"
            return ResponseResult(success=True, message=msg)

        quarantine_path = Path(quarantined)
        if not quarantine_path.exists():
            return ResponseResult(
                success=False,
                message=f"Quarantined file not found: {quarantined}",
                error="File missing",
            )

        try:
            shutil.move(str(quarantine_path), str(original))
        except OSError as exc:
            return ResponseResult(
                success=False,
                message=f"Failed to restore file",
                error=str(exc),
            )

        msg = f"Restored {quarantined} -> {original}"
        logger.info(msg)
        return ResponseResult(success=True, message=msg)

    def describe(self) -> str:
        """Describe what this action will do."""
        prefix = "[DRY RUN] " if self._dry_run else ""
        return f"{prefix}Move {self._file_path} to quarantine directory"
