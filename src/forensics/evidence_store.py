"""Forensic evidence archival with integrity verification.

Stores evidence files in timestamped directories and maintains
SHA-256 manifests for tamper detection.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.core.config import AppConfig
from src.core.database import Database
from src.core.enums import EvidenceType
from src.core.exceptions import EvidenceIntegrityError, ForensicError
from src.core.models import Evidence
from src.forensics.file_hasher import compute_sha256, compute_sha256_bytes

logger = logging.getLogger(__name__)


class EvidenceStore:
    """Manage forensic evidence storage with integrity guarantees.

    Each alert's evidence is stored in a dedicated directory with
    a SHA-256 manifest for tamper detection.

    Args:
        config: Application configuration.
        database: Database instance for persistence.
    """

    def __init__(self, config: AppConfig, database: Database) -> None:
        self._evidence_dir = Path(config.forensics.evidence_dir)
        self._db = database

    def store_evidence(
        self,
        alert_uid: str,
        evidence_type: EvidenceType,
        data: dict[str, Any] | list[Any],
        filename: str,
    ) -> Evidence:
        """Store evidence data as a JSON file with integrity hash.

        Args:
            alert_uid: UID of the associated alert.
            evidence_type: Type of evidence.
            data: Evidence data to serialize.
            filename: Name for the evidence file.

        Returns:
            Evidence record with file path and integrity hash.

        Raises:
            ForensicError: If storage fails.
        """
        if not alert_uid:
            raise ValueError("alert_uid must not be empty")
        if not filename:
            raise ValueError("filename must not be empty")

        alert_dir = self._evidence_dir / alert_uid
        alert_dir.mkdir(parents=True, exist_ok=True)

        file_path = alert_dir / filename
        try:
            content = json.dumps(data, indent=2, default=str).encode("utf-8")
            file_path.write_bytes(content)
        except (OSError, TypeError) as exc:
            raise ForensicError(f"Failed to write evidence file {file_path}: {exc}") from exc

        sha256 = compute_sha256(file_path)

        evidence = Evidence(
            alert_uid=alert_uid,
            evidence_type=evidence_type,
            file_path=str(file_path),
            sha256_hash=sha256,
        )

        self._db.insert_evidence(evidence)
        logger.info(
            "Evidence stored: %s (%s) -> %s",
            evidence_type.value,
            sha256[:12],
            file_path,
        )

        return evidence

    def generate_manifest(self, alert_uid: str) -> str:
        """Generate and store a manifest for all evidence of an alert.

        The manifest lists all evidence files with their SHA-256 hashes.
        The manifest itself is also hashed for top-level integrity.

        Args:
            alert_uid: UID of the alert.

        Returns:
            SHA-256 hash of the manifest file.

        Raises:
            ForensicError: If manifest generation fails.
        """
        alert_dir = self._evidence_dir / alert_uid
        if not alert_dir.exists():
            raise ForensicError(f"Evidence directory not found: {alert_dir}")

        records = self._db.get_evidence_for_alert(alert_uid)
        manifest_entries = []

        for record in records:
            manifest_entries.append({
                "evidence_uid": record["evidence_uid"],
                "evidence_type": record["evidence_type"],
                "file_path": record["file_path"],
                "sha256_hash": record["sha256_hash"],
                "collected_at": record["collected_at"],
            })

        manifest = {
            "alert_uid": alert_uid,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "evidence_count": len(manifest_entries),
            "entries": manifest_entries,
        }

        manifest_path = alert_dir / "manifest.json"
        try:
            content = json.dumps(manifest, indent=2).encode("utf-8")
            manifest_path.write_bytes(content)
        except OSError as exc:
            raise ForensicError(f"Failed to write manifest: {exc}") from exc

        manifest_hash = compute_sha256(manifest_path)
        logger.info(
            "Manifest generated for alert %s: %d entries, hash %s",
            alert_uid,
            len(manifest_entries),
            manifest_hash[:12],
        )

        return manifest_hash

    def verify_integrity(self, alert_uid: str) -> bool:
        """Verify integrity of all evidence files for an alert.

        Recalculates SHA-256 hashes and compares with stored values.

        Args:
            alert_uid: UID of the alert to verify.

        Returns:
            True if all hashes match.

        Raises:
            EvidenceIntegrityError: If any file has been tampered with.
        """
        records = self._db.get_evidence_for_alert(alert_uid)

        for record in records:
            file_path = Path(record["file_path"])
            expected_hash = record["sha256_hash"]

            if not file_path.exists():
                raise EvidenceIntegrityError(
                    f"Evidence file missing: {file_path}"
                )

            actual_hash = compute_sha256(file_path)
            hashes_match = actual_hash == expected_hash
            if not hashes_match:
                raise EvidenceIntegrityError(
                    f"Hash mismatch for {file_path}: "
                    f"expected {expected_hash[:12]}..., got {actual_hash[:12]}..."
                )

        logger.info(
            "Integrity verified for alert %s: %d evidence files OK",
            alert_uid,
            len(records),
        )
        return True
