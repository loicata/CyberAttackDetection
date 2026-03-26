"""In-process asynchronous event bus using asyncio queues."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any

from src.core.models import RawEvent

logger = logging.getLogger(__name__)

# Type alias for subscriber callbacks
Subscriber = Callable[[RawEvent], Coroutine[Any, Any, None]]


class EventBus:
    """Asynchronous pub/sub event bus for decoupled communication.

    Detectors publish RawEvents; analysis modules subscribe to receive them.
    Uses a fan-out pattern: each event is delivered to all subscribers.

    Attributes:
        _subscribers: List of registered subscriber callbacks.
        _queue: Internal asyncio queue for buffering events.
        _running: Whether the dispatch loop is active.
        _max_queue_size: Maximum number of events to buffer.
    """

    def __init__(self, max_queue_size: int = 10000) -> None:
        """Initialize the event bus.

        Args:
            max_queue_size: Maximum events to buffer before backpressure.
                Must be a positive integer.

        Raises:
            ValueError: If max_queue_size is not positive.
        """
        if not isinstance(max_queue_size, int) or max_queue_size <= 0:
            raise ValueError(f"max_queue_size must be a positive integer, got {max_queue_size!r}")

        self._subscribers: list[Subscriber] = []
        self._queue: asyncio.Queue[RawEvent | None] = asyncio.Queue(maxsize=max_queue_size)
        self._running = False
        self._max_queue_size = max_queue_size
        self._dispatch_task: asyncio.Task[None] | None = None
        self._event_count = 0
        self._error_count = 0

    def subscribe(self, callback: Subscriber) -> None:
        """Register a subscriber to receive events.

        Args:
            callback: Async callable that accepts a RawEvent.

        Raises:
            TypeError: If callback is not callable.
        """
        if not callable(callback):
            raise TypeError(f"Subscriber must be callable, got {type(callback).__name__}")
        self._subscribers.append(callback)
        logger.debug("Subscriber registered: %s", callback.__qualname__)

    def unsubscribe(self, callback: Subscriber) -> None:
        """Remove a subscriber.

        Args:
            callback: The subscriber to remove.
        """
        try:
            self._subscribers.remove(callback)
            logger.debug("Subscriber removed: %s", callback.__qualname__)
        except ValueError:
            logger.warning("Subscriber not found for removal: %s", callback.__qualname__)

    async def publish(self, event: RawEvent) -> None:
        """Publish an event to the bus.

        Events are queued and dispatched asynchronously to all subscribers.

        Args:
            event: The RawEvent to publish.

        Raises:
            TypeError: If event is not a RawEvent.
            asyncio.QueueFull: If the queue is at capacity.
        """
        if not isinstance(event, RawEvent):
            raise TypeError(f"Expected RawEvent, got {type(event).__name__}")

        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.error(
                "Event bus queue full (%d events). Dropping event %s",
                self._max_queue_size,
                event.event_uid,
            )
            raise

    async def start(self) -> None:
        """Start the dispatch loop.

        Events are consumed from the queue and fanned out to all subscribers.
        """
        if self._running:
            logger.warning("Event bus already running")
            return

        self._running = True
        self._dispatch_task = asyncio.create_task(self._dispatch_loop())
        logger.info("Event bus started")

    async def stop(self) -> None:
        """Stop the dispatch loop gracefully.

        Sends a sentinel None to unblock the queue, then waits for
        the dispatch task to complete.
        """
        if not self._running:
            return

        self._running = False
        await self._queue.put(None)

        if self._dispatch_task is not None:
            await self._dispatch_task
            self._dispatch_task = None

        logger.info(
            "Event bus stopped. Processed %d events, %d errors",
            self._event_count,
            self._error_count,
        )

    async def _dispatch_loop(self) -> None:
        """Internal loop that consumes events and fans out to subscribers."""
        while self._running:
            event = await self._queue.get()
            if event is None:
                break
            await self._fan_out(event)
            self._event_count += 1

    async def _fan_out(self, event: RawEvent) -> None:
        """Deliver an event to all subscribers.

        Errors in individual subscribers are logged but do not
        prevent delivery to other subscribers.

        Args:
            event: The event to deliver.
        """
        for subscriber in self._subscribers:
            try:
                await subscriber(event)
            except Exception:
                self._error_count += 1
                logger.exception(
                    "Subscriber %s failed processing event %s",
                    subscriber.__qualname__,
                    event.event_uid,
                )

    @property
    def is_running(self) -> bool:
        """Whether the dispatch loop is active."""
        return self._running

    @property
    def queue_size(self) -> int:
        """Current number of events waiting in the queue."""
        return self._queue.qsize()

    @property
    def event_count(self) -> int:
        """Total number of events processed since start."""
        return self._event_count

    @property
    def subscriber_count(self) -> int:
        """Number of registered subscribers."""
        return len(self._subscribers)
