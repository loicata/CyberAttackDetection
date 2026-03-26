"""Abstract base class for all detectors."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod

from src.core.enums import DetectorState
from src.core.event_bus import EventBus
from src.core.models import RawEvent

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """Abstract base for detection modules.

    Each detector runs as an asyncio task, periodically polls for
    new events, and publishes them to the event bus.

    Args:
        name: Human-readable name for this detector.
        event_bus: The shared event bus to publish events to.
        polling_interval: Seconds between polling cycles.
    """

    def __init__(
        self,
        name: str,
        event_bus: EventBus,
        polling_interval: float = 5.0,
    ) -> None:
        if not name:
            raise ValueError("Detector name must not be empty")
        if not isinstance(event_bus, EventBus):
            raise TypeError(f"Expected EventBus, got {type(event_bus).__name__}")
        if polling_interval <= 0:
            raise ValueError(f"Polling interval must be positive, got {polling_interval}")

        self._name = name
        self._event_bus = event_bus
        self._polling_interval = polling_interval
        self._state = DetectorState.STOPPED
        self._task: asyncio.Task[None] | None = None
        self._cycle_count = 0
        self._error_count = 0

    @property
    def name(self) -> str:
        """Human-readable detector name."""
        return self._name

    @property
    def state(self) -> DetectorState:
        """Current operational state."""
        return self._state

    @property
    def cycle_count(self) -> int:
        """Number of completed polling cycles."""
        return self._cycle_count

    async def start(self) -> None:
        """Start the detector's polling loop.

        Raises:
            RuntimeError: If the detector is already running.
        """
        if self._state == DetectorState.RUNNING:
            logger.warning("Detector %s is already running", self._name)
            return

        self._state = DetectorState.STARTING
        logger.info("Starting detector: %s", self._name)

        try:
            await self._initialize()
            self._state = DetectorState.RUNNING
            self._task = asyncio.create_task(self._polling_loop())
            logger.info("Detector %s started successfully", self._name)
        except Exception as exc:
            self._state = DetectorState.ERROR
            logger.error("Failed to start detector %s: %s", self._name, exc)
            raise

    async def stop(self) -> None:
        """Stop the detector gracefully."""
        if self._state not in (DetectorState.RUNNING, DetectorState.ERROR):
            return

        self._state = DetectorState.STOPPING
        logger.info("Stopping detector: %s", self._name)

        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        await self._cleanup()
        self._state = DetectorState.STOPPED
        logger.info(
            "Detector %s stopped. Cycles: %d, Errors: %d",
            self._name,
            self._cycle_count,
            self._error_count,
        )

    async def _polling_loop(self) -> None:
        """Main loop that repeatedly calls poll() and publishes events."""
        while self._state == DetectorState.RUNNING:
            try:
                events = await self._poll()
                for event in events:
                    await self._event_bus.publish(event)
                self._cycle_count += 1
            except asyncio.CancelledError:
                raise
            except Exception:
                self._error_count += 1
                logger.exception(
                    "Error in detector %s during poll cycle %d",
                    self._name,
                    self._cycle_count,
                )
                if self._error_count > 10:
                    logger.error(
                        "Detector %s exceeded error threshold, entering error state",
                        self._name,
                    )
                    self._state = DetectorState.ERROR
                    return

            await asyncio.sleep(self._polling_interval)

    async def _initialize(self) -> None:
        """Optional initialization hook called before polling starts.

        Subclasses can override this to set up resources.
        Default implementation does nothing.
        """

    async def _cleanup(self) -> None:
        """Optional cleanup hook called after polling stops.

        Subclasses can override this to release resources.
        Default implementation does nothing.
        """

    @abstractmethod
    async def _poll(self) -> list[RawEvent]:
        """Poll for new events.

        Must be implemented by each detector. Called once per
        polling interval. Should return a list of new events
        detected since the last call.

        Returns:
            List of RawEvent objects detected in this cycle.
        """
        ...

    def health_check(self) -> dict[str, object]:
        """Return health status of this detector.

        Returns:
            Dict with name, state, cycle_count, and error_count.
        """
        return {
            "name": self._name,
            "state": self._state.value,
            "cycle_count": self._cycle_count,
            "error_count": self._error_count,
        }
