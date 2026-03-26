"""SQLite database manager with WAL mode, migrations, and CRUD operations."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any

from src.core.enums import AlertStatus
from src.core.exceptions import DatabaseError
from src.core.models import Alert, Evidence, ResponseRecord

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_uid       TEXT    NOT NULL UNIQUE,
    alert_type      TEXT    NOT NULL,
    severity        TEXT    NOT NULL,
    score           INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100),
    title           TEXT    NOT NULL,
    description     TEXT    NOT NULL,
    source_ip       TEXT,
    source_port     INTEGER,
    dest_ip         TEXT,
    dest_port       INTEGER,
    process_name    TEXT,
    process_pid     INTEGER,
    file_path       TEXT,
    raw_event_json  TEXT    NOT NULL,
    intel_json      TEXT,
    is_false_positive INTEGER NOT NULL DEFAULT 0,
    status          TEXT    NOT NULL DEFAULT 'new',
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    resolved_at     TEXT,
    correlated_uids_json TEXT NOT NULL DEFAULT '[]',
    occurrence_count INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);

CREATE TABLE IF NOT EXISTS evidence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_uid    TEXT    NOT NULL UNIQUE,
    alert_uid       TEXT    NOT NULL,
    evidence_type   TEXT    NOT NULL,
    file_path       TEXT    NOT NULL,
    sha256_hash     TEXT    NOT NULL,
    collected_at    TEXT    NOT NULL,
    metadata_json   TEXT
);

CREATE INDEX IF NOT EXISTS idx_evidence_alert ON evidence(alert_uid);

CREATE TABLE IF NOT EXISTS baselines (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    category        TEXT    NOT NULL,
    key             TEXT    NOT NULL,
    value_json      TEXT    NOT NULL,
    sample_count    INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL,
    UNIQUE(category, key)
);

CREATE TABLE IF NOT EXISTS whitelist (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_type      TEXT    NOT NULL,
    value           TEXT    NOT NULL,
    reason          TEXT    NOT NULL,
    added_by        TEXT    NOT NULL DEFAULT 'system',
    created_at      TEXT    NOT NULL,
    UNIQUE(entry_type, value)
);

CREATE TABLE IF NOT EXISTS response_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    response_uid    TEXT    NOT NULL UNIQUE,
    alert_uid       TEXT    NOT NULL,
    action_type     TEXT    NOT NULL,
    parameters_json TEXT    NOT NULL,
    rollback_json   TEXT,
    status          TEXT    NOT NULL DEFAULT 'pending',
    executed_at     TEXT,
    rolled_back_at  TEXT,
    error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_response_alert ON response_log(alert_uid);

CREATE TABLE IF NOT EXISTS suricata_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uid       TEXT    NOT NULL UNIQUE,
    timestamp       TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    src_ip          TEXT,
    src_port        INTEGER,
    dest_ip         TEXT,
    dest_port       INTEGER,
    signature_id    INTEGER,
    signature       TEXT,
    severity        INTEGER,
    raw_json        TEXT    NOT NULL,
    correlated_alert_uid TEXT,
    ingested_at     TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_suricata_ts ON suricata_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_suricata_sig ON suricata_events(signature_id);
"""


class Database:
    """Thread-safe SQLite database manager.

    Uses WAL mode for concurrent reads and a write lock
    to serialize all write operations.

    Args:
        db_path: Path to the SQLite database file.
        wal_mode: Whether to enable WAL journal mode.
        busy_timeout_ms: SQLite busy timeout in milliseconds.
    """

    def __init__(
        self,
        db_path: str | Path,
        wal_mode: bool = True,
        busy_timeout_ms: int = 5000,
    ) -> None:
        if not db_path:
            raise DatabaseError("Database path must not be empty")

        self._db_path = Path(db_path)
        self._wal_mode = wal_mode
        self._busy_timeout_ms = busy_timeout_ms
        self._write_lock = threading.Lock()
        self._initialized = False

    def initialize(self) -> None:
        """Create database file, apply schema, and set pragmas.

        Raises:
            DatabaseError: If initialization fails.
        """
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = self._connect()
            try:
                if self._wal_mode:
                    conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
                conn.executescript(SCHEMA_SQL)
                self._ensure_schema_version(conn)
                conn.commit()
            finally:
                conn.close()
            self._initialized = True
            logger.info("Database initialized at %s", self._db_path)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to initialize database: {exc}") from exc

    def _connect(self) -> sqlite3.Connection:
        """Open a new connection to the database.

        Returns:
            A sqlite3 Connection.

        Raises:
            DatabaseError: If connection fails.
        """
        try:
            conn = sqlite3.connect(str(self._db_path), timeout=self._busy_timeout_ms / 1000)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            return conn
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to connect to database: {exc}") from exc

    def _ensure_schema_version(self, conn: sqlite3.Connection) -> None:
        """Insert or check schema version."""
        cursor = conn.execute("SELECT COUNT(*) FROM schema_version")
        count = cursor.fetchone()[0]
        if count == 0:
            conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))

    def _ensure_initialized(self) -> None:
        """Raise if database has not been initialized."""
        if not self._initialized:
            raise DatabaseError("Database not initialized. Call initialize() first.")

    def insert_alert(self, alert: Alert) -> None:
        """Persist an alert to the database.

        Args:
            alert: The Alert to insert.

        Raises:
            DatabaseError: If the insert fails.
        """
        self._ensure_initialized()
        raw_event_dict = asdict(alert.raw_event)
        intel_json = json.dumps(alert.intel_data) if alert.intel_data else None

        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO alerts (
                        alert_uid, alert_type, severity, score, title, description,
                        source_ip, source_port, dest_ip, dest_port,
                        process_name, process_pid, file_path,
                        raw_event_json, intel_json, is_false_positive, status,
                        created_at, updated_at, resolved_at,
                        correlated_uids_json, occurrence_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        alert.alert_uid,
                        alert.alert_type.value,
                        alert.severity.value,
                        alert.score,
                        alert.title,
                        alert.description,
                        alert.source_ip,
                        alert.source_port,
                        alert.dest_ip,
                        alert.dest_port,
                        alert.process_name,
                        alert.process_pid,
                        alert.file_path,
                        json.dumps(raw_event_dict),
                        intel_json,
                        1 if alert.is_false_positive else 0,
                        alert.status.value,
                        alert.created_at,
                        alert.updated_at,
                        alert.resolved_at,
                        json.dumps(alert.correlated_event_uids),
                        alert.occurrence_count,
                    ),
                )
                conn.commit()
                logger.debug("Inserted alert %s", alert.alert_uid)
            except sqlite3.IntegrityError as exc:
                raise DatabaseError(f"Alert already exists: {alert.alert_uid}") from exc
            except sqlite3.Error as exc:
                raise DatabaseError(f"Failed to insert alert: {exc}") from exc
            finally:
                conn.close()

    def update_alert_status(
        self, alert_uid: str, status: AlertStatus, updated_at: str
    ) -> None:
        """Update the status of an alert.

        Args:
            alert_uid: The alert's unique identifier.
            status: New status.
            updated_at: ISO 8601 timestamp of the update.

        Raises:
            DatabaseError: If the update fails.
        """
        self._ensure_initialized()
        with self._write_lock:
            conn = self._connect()
            try:
                cursor = conn.execute(
                    "UPDATE alerts SET status = ?, updated_at = ? WHERE alert_uid = ?",
                    (status.value, updated_at, alert_uid),
                )
                if cursor.rowcount == 0:
                    raise DatabaseError(f"Alert not found: {alert_uid}")
                conn.commit()
            except sqlite3.Error as exc:
                raise DatabaseError(f"Failed to update alert status: {exc}") from exc
            finally:
                conn.close()

    def get_alert_by_uid(self, alert_uid: str) -> Alert | None:
        """Retrieve a single alert by its unique identifier.

        Args:
            alert_uid: The alert UID to look up.

        Returns:
            Alert object if found, None otherwise.
        """
        self._ensure_initialized()
        conn = self._connect()
        try:
            cursor = conn.execute(
                "SELECT * FROM alerts WHERE alert_uid = ?", (alert_uid,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_alert(dict(row))
        finally:
            conn.close()

    def _row_to_alert(self, row: dict[str, Any]) -> Alert:
        """Convert a database row dict to an Alert object.

        Args:
            row: Dict from database query.

        Returns:
            Alert instance.
        """
        import json as _json
        from src.core.enums import AlertSeverity, AlertType
        from src.core.models import RawEvent

        raw_event_data = _json.loads(row.get("raw_event_json", "{}"))
        raw_event = RawEvent(
            event_type=AlertType(row.get("alert_type", "unknown")),
            data=raw_event_data,
            source_ip=row.get("source_ip"),
            dest_ip=row.get("dest_ip"),
        )

        return Alert(
            alert_uid=row["alert_uid"],
            alert_type=AlertType(row.get("alert_type", "unknown")),
            severity=AlertSeverity(row.get("severity", "INFO")),
            score=row.get("score", 0),
            title=row.get("title", ""),
            description=row.get("description", ""),
            raw_event=raw_event,
            source_ip=row.get("source_ip"),
            source_port=row.get("source_port"),
            dest_ip=row.get("dest_ip"),
            dest_port=row.get("dest_port"),
            process_name=row.get("process_name"),
            process_pid=row.get("process_pid"),
            file_path=row.get("file_path"),
            created_at=row.get("created_at", ""),
            intel_data=_json.loads(row.get("intel_json") or "null"),
        )

    def get_alerts(
        self,
        status: AlertStatus | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Retrieve alerts from the database.

        Args:
            status: Filter by status if provided.
            limit: Maximum number of alerts to return.

        Returns:
            List of alert rows as dicts.
        """
        self._ensure_initialized()
        conn = self._connect()
        try:
            if status is not None:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status.value, limit),
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                )
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def insert_evidence(self, evidence: Evidence) -> None:
        """Persist an evidence record.

        Args:
            evidence: The Evidence to insert.

        Raises:
            DatabaseError: If the insert fails.
        """
        self._ensure_initialized()
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO evidence (
                        evidence_uid, alert_uid, evidence_type, file_path,
                        sha256_hash, collected_at, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        evidence.evidence_uid,
                        evidence.alert_uid,
                        evidence.evidence_type.value,
                        evidence.file_path,
                        evidence.sha256_hash,
                        evidence.collected_at,
                        json.dumps(evidence.metadata) if evidence.metadata else None,
                    ),
                )
                conn.commit()
                logger.debug("Inserted evidence %s", evidence.evidence_uid)
            except sqlite3.Error as exc:
                raise DatabaseError(f"Failed to insert evidence: {exc}") from exc
            finally:
                conn.close()

    def get_evidence_for_alert(self, alert_uid: str) -> list[dict[str, Any]]:
        """Retrieve all evidence for a given alert.

        Args:
            alert_uid: The alert's unique identifier.

        Returns:
            List of evidence rows as dicts.
        """
        self._ensure_initialized()
        conn = self._connect()
        try:
            cursor = conn.execute(
                "SELECT * FROM evidence WHERE alert_uid = ? ORDER BY collected_at",
                (alert_uid,),
            )
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def insert_response(self, record: ResponseRecord) -> None:
        """Persist a response action record.

        Args:
            record: The ResponseRecord to insert.

        Raises:
            DatabaseError: If the insert fails.
        """
        self._ensure_initialized()
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO response_log (
                        response_uid, alert_uid, action_type, parameters_json,
                        rollback_json, status, executed_at, rolled_back_at, error_message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record.response_uid,
                        record.alert_uid,
                        record.action_type.value,
                        json.dumps(record.parameters),
                        json.dumps(record.rollback_data) if record.rollback_data else None,
                        record.status.value,
                        record.executed_at,
                        record.rolled_back_at,
                        record.error_message,
                    ),
                )
                conn.commit()
            except sqlite3.Error as exc:
                raise DatabaseError(f"Failed to insert response: {exc}") from exc
            finally:
                conn.close()

    def update_response_status(
        self,
        response_uid: str,
        status: str,
        executed_at: str | None = None,
        rolled_back_at: str | None = None,
        rollback_json: str | None = None,
        error_message: str | None = None,
    ) -> None:
        """Update a response record's status and timestamps.

        Args:
            response_uid: The response's unique identifier.
            status: New status string.
            executed_at: Execution timestamp if applicable.
            rolled_back_at: Rollback timestamp if applicable.
            rollback_json: Rollback data JSON if applicable.
            error_message: Error message if applicable.

        Raises:
            DatabaseError: If the update fails.
        """
        self._ensure_initialized()
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    """UPDATE response_log SET
                        status = ?,
                        executed_at = COALESCE(?, executed_at),
                        rolled_back_at = COALESCE(?, rolled_back_at),
                        rollback_json = COALESCE(?, rollback_json),
                        error_message = COALESCE(?, error_message)
                    WHERE response_uid = ?""",
                    (status, executed_at, rolled_back_at, rollback_json, error_message,
                     response_uid),
                )
                conn.commit()
            except sqlite3.Error as exc:
                raise DatabaseError(f"Failed to update response: {exc}") from exc
            finally:
                conn.close()

    def upsert_baseline(
        self, category: str, key: str, value_json: str, timestamp: str
    ) -> None:
        """Insert or update a baseline entry.

        Args:
            category: Baseline category (process/network/filesystem).
            key: Unique key within the category.
            value_json: Serialized statistical profile.
            timestamp: ISO 8601 timestamp.

        Raises:
            DatabaseError: If the operation fails.
        """
        self._ensure_initialized()
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO baselines (category, key, value_json, sample_count,
                        first_seen, last_seen)
                    VALUES (?, ?, ?, 1, ?, ?)
                    ON CONFLICT(category, key) DO UPDATE SET
                        value_json = excluded.value_json,
                        sample_count = sample_count + 1,
                        last_seen = excluded.last_seen""",
                    (category, key, value_json, timestamp, timestamp),
                )
                conn.commit()
            except sqlite3.Error as exc:
                raise DatabaseError(f"Failed to upsert baseline: {exc}") from exc
            finally:
                conn.close()

    def get_baseline(self, category: str, key: str) -> dict[str, Any] | None:
        """Retrieve a baseline entry.

        Args:
            category: Baseline category.
            key: Entry key.

        Returns:
            Baseline row as dict, or None if not found.
        """
        self._ensure_initialized()
        conn = self._connect()
        try:
            cursor = conn.execute(
                "SELECT * FROM baselines WHERE category = ? AND key = ?",
                (category, key),
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def upsert_whitelist(
        self, entry_type: str, value: str, reason: str, added_by: str, created_at: str
    ) -> None:
        """Insert or update a whitelist entry.

        Args:
            entry_type: Type of entry (process/ip/hash/path).
            value: The whitelisted value.
            reason: Reason for whitelisting.
            added_by: Who added the entry.
            created_at: ISO 8601 timestamp.

        Raises:
            DatabaseError: If the operation fails.
        """
        self._ensure_initialized()
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO whitelist (entry_type, value, reason, added_by, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(entry_type, value) DO UPDATE SET
                        reason = excluded.reason,
                        added_by = excluded.added_by""",
                    (entry_type, value, reason, added_by, created_at),
                )
                conn.commit()
            except sqlite3.Error as exc:
                raise DatabaseError(f"Failed to upsert whitelist: {exc}") from exc
            finally:
                conn.close()

    def get_whitelist(self, entry_type: str | None = None) -> list[dict[str, Any]]:
        """Retrieve whitelist entries.

        Args:
            entry_type: Filter by type if provided.

        Returns:
            List of whitelist rows as dicts.
        """
        self._ensure_initialized()
        conn = self._connect()
        try:
            if entry_type is not None:
                cursor = conn.execute(
                    "SELECT * FROM whitelist WHERE entry_type = ?",
                    (entry_type,),
                )
            else:
                cursor = conn.execute("SELECT * FROM whitelist")
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def close(self) -> None:
        """Mark database as closed. Connections are managed per-call."""
        self._initialized = False
        logger.info("Database closed")
