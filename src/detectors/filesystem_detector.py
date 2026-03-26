"""File system monitor using watchdog.

Detects:
- New executable files in critical directories (System32, Startup)
- Modification of existing system files
- Creation of files with suspicious extensions
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from src.core.config import AppConfig
from src.core.enums import AlertType
from src.core.event_bus import EventBus
from src.core.models import RawEvent
from src.detectors.base import BaseDetector

logger = logging.getLogger(__name__)


class _FileEventHandler(FileSystemEventHandler):
    """Watchdog handler that queues events for async processing.

    Args:
        suspicious_extensions: Set of file extensions to flag.
        sync_queue: Thread-safe queue to pass events to async code.
    """

    def __init__(
        self,
        suspicious_extensions: set[str],
        sync_queue: asyncio.Queue[dict[str, Any]],
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        super().__init__()
        self._suspicious_extensions = suspicious_extensions
        self._sync_queue = sync_queue
        self._loop = loop

    def on_created(self, event: FileSystemEvent) -> None:
        """Handle file creation events."""
        if event.is_directory:
            return
        self._enqueue(event, "created")

    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle file modification events."""
        if event.is_directory:
            return
        self._enqueue(event, "modified")

    def on_moved(self, event: FileSystemEvent) -> None:
        """Handle file move/rename events."""
        if event.is_directory:
            return
        self._enqueue(event, "moved")

    # System binaries accessed by our own detectors/forensics — always ignore
    _SELF_TRIGGERED_BINARIES = {
        "wevtutil.exe", "reg.exe", "schtasks.exe", "taskkill.exe",
        "netsh.exe", "nslookup.exe", "tracert.exe", "whois.exe",
    }

    def _enqueue(self, event: FileSystemEvent, action: str) -> None:
        """Put event data on the queue if it has a suspicious extension.

        Filters out:
        - Non-suspicious file extensions
        - 'modified' events (only 'created' and 'moved' are meaningful)
        - Known system binaries triggered by our own subprocess calls

        Args:
            event: The watchdog filesystem event.
            action: Type of action (created/modified/moved).
        """
        # Only alert on new files or moves, not access/modify of existing files
        if action == "modified":
            return

        src_path = event.src_path
        extension = Path(src_path).suffix.lower()
        is_suspicious_ext = extension in self._suspicious_extensions

        if not is_suspicious_ext:
            return

        # Ignore known system binaries triggered by our own tools
        filename = Path(src_path).name.lower()
        if filename in self._SELF_TRIGGERED_BINARIES:
            return

        data = {
            "action": action,
            "src_path": src_path,
            "extension": extension,
            "is_directory": False,
        }

        if hasattr(event, "dest_path"):
            data["dest_path"] = event.dest_path

        try:
            self._loop.call_soon_threadsafe(self._sync_queue.put_nowait, data)
        except asyncio.QueueFull:
            logger.warning("Filesystem event queue full, dropping event: %s", src_path)


class FilesystemDetector(BaseDetector):
    """Monitor critical filesystem paths for suspicious changes.

    Args:
        event_bus: Event bus to publish detected events.
        config: Application configuration.
    """

    def __init__(self, event_bus: EventBus, config: AppConfig) -> None:
        super().__init__(
            name="filesystem_detector",
            event_bus=event_bus,
            polling_interval=config.polling_interval_seconds,
        )
        self._config = config
        self._watched_paths = list(config.watched_paths)
        self._suspicious_extensions = {e.lower() for e in config.suspicious_extensions}
        self._observer: Observer | None = None
        self._event_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1000)

    async def _initialize(self) -> None:
        """Set up watchdog observer on configured paths."""
        loop = asyncio.get_running_loop()
        handler = _FileEventHandler(
            suspicious_extensions=self._suspicious_extensions,
            sync_queue=self._event_queue,
            loop=loop,
        )

        self._observer = Observer()
        paths_watched = 0

        for path_str in self._watched_paths:
            path = Path(path_str)
            if not path.exists():
                logger.warning("Watched path does not exist, skipping: %s", path_str)
                continue
            if not path.is_dir():
                logger.warning("Watched path is not a directory, skipping: %s", path_str)
                continue

            self._observer.schedule(handler, str(path), recursive=True)
            paths_watched += 1
            logger.debug("Watching directory: %s", path_str)

        if paths_watched == 0:
            logger.warning("No valid paths to watch for filesystem detector")
            return

        await asyncio.to_thread(self._observer.start)
        logger.info(
            "Filesystem detector watching %d directories", paths_watched
        )

    async def _cleanup(self) -> None:
        """Stop the watchdog observer."""
        if self._observer is not None:
            self._observer.stop()
            await asyncio.to_thread(self._observer.join, timeout=5)
            self._observer = None

    async def _poll(self) -> list[RawEvent]:
        """Drain queued filesystem events and convert to RawEvents.

        Returns:
            List of RawEvent for suspicious filesystem activity.
        """
        events: list[RawEvent] = []

        while not self._event_queue.empty():
            try:
                fs_event = self._event_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

            src_path = fs_event.get("src_path", "")
            is_system32 = "system32" in src_path.lower() or "syswow64" in src_path.lower()
            rule = "filesystem_change_system32" if is_system32 else "filesystem_change"

            events.append(
                RawEvent(
                    event_type=AlertType.FILESYSTEM,
                    data={
                        "rule": rule,
                        **fs_event,
                    },
                    file_path=src_path,
                )
            )

            logger.info(
                "Filesystem event: %s %s (ext: %s)",
                fs_event.get("action"),
                src_path,
                fs_event.get("extension"),
            )

        return events
