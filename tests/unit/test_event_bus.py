"""Tests for the asynchronous event bus."""

from __future__ import annotations

import asyncio

import pytest

from src.core.enums import AlertType
from src.core.event_bus import EventBus
from src.core.models import RawEvent


@pytest.fixture
def make_event() -> RawEvent:
    """Create a simple test event."""
    return RawEvent(event_type=AlertType.NETWORK, data={"test": True})


class TestEventBusInit:
    """Tests for EventBus initialization."""

    def test_default_creation(self) -> None:
        bus = EventBus()
        assert bus.subscriber_count == 0
        assert bus.event_count == 0
        assert not bus.is_running

    def test_custom_queue_size(self) -> None:
        bus = EventBus(max_queue_size=50)
        assert bus.queue_size == 0

    def test_invalid_queue_size_zero(self) -> None:
        with pytest.raises(ValueError, match="positive integer"):
            EventBus(max_queue_size=0)

    def test_invalid_queue_size_negative(self) -> None:
        with pytest.raises(ValueError, match="positive integer"):
            EventBus(max_queue_size=-5)

    def test_invalid_queue_size_string(self) -> None:
        with pytest.raises(ValueError, match="positive integer"):
            EventBus(max_queue_size="big")  # type: ignore[arg-type]


class TestSubscription:
    """Tests for subscribe/unsubscribe."""

    def test_subscribe(self) -> None:
        bus = EventBus()

        async def handler(event: RawEvent) -> None:
            pass

        bus.subscribe(handler)
        assert bus.subscriber_count == 1

    def test_unsubscribe(self) -> None:
        bus = EventBus()

        async def handler(event: RawEvent) -> None:
            pass

        bus.subscribe(handler)
        bus.unsubscribe(handler)
        assert bus.subscriber_count == 0

    def test_unsubscribe_nonexistent(self) -> None:
        bus = EventBus()

        async def handler(event: RawEvent) -> None:
            pass

        bus.unsubscribe(handler)  # Should not raise
        assert bus.subscriber_count == 0

    def test_subscribe_non_callable_raises(self) -> None:
        bus = EventBus()
        with pytest.raises(TypeError, match="callable"):
            bus.subscribe("not_a_function")  # type: ignore[arg-type]


class TestPublishAndDispatch:
    """Tests for event publishing and dispatch."""

    @pytest.mark.asyncio
    async def test_publish_and_receive(self, make_event: RawEvent) -> None:
        bus = EventBus(max_queue_size=10)
        received: list[RawEvent] = []

        async def handler(event: RawEvent) -> None:
            received.append(event)

        bus.subscribe(handler)
        await bus.start()
        await bus.publish(make_event)
        await asyncio.sleep(0.1)
        await bus.stop()

        assert len(received) == 1
        assert received[0].event_uid == make_event.event_uid

    @pytest.mark.asyncio
    async def test_fan_out_to_multiple_subscribers(self, make_event: RawEvent) -> None:
        bus = EventBus(max_queue_size=10)
        received_a: list[RawEvent] = []
        received_b: list[RawEvent] = []

        async def handler_a(event: RawEvent) -> None:
            received_a.append(event)

        async def handler_b(event: RawEvent) -> None:
            received_b.append(event)

        bus.subscribe(handler_a)
        bus.subscribe(handler_b)
        await bus.start()
        await bus.publish(make_event)
        await asyncio.sleep(0.1)
        await bus.stop()

        assert len(received_a) == 1
        assert len(received_b) == 1

    @pytest.mark.asyncio
    async def test_subscriber_error_does_not_block_others(
        self, make_event: RawEvent
    ) -> None:
        bus = EventBus(max_queue_size=10)
        received: list[RawEvent] = []

        async def failing_handler(event: RawEvent) -> None:
            raise RuntimeError("Subscriber failed")

        async def good_handler(event: RawEvent) -> None:
            received.append(event)

        bus.subscribe(failing_handler)
        bus.subscribe(good_handler)
        await bus.start()
        await bus.publish(make_event)
        await asyncio.sleep(0.1)
        await bus.stop()

        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_publish_non_event_raises(self) -> None:
        bus = EventBus()
        with pytest.raises(TypeError, match="RawEvent"):
            await bus.publish("not_an_event")  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_event_count_tracks(self) -> None:
        bus = EventBus(max_queue_size=10)

        async def noop(event: RawEvent) -> None:
            pass

        bus.subscribe(noop)
        await bus.start()

        for _ in range(5):
            event = RawEvent(event_type=AlertType.PROCESS, data={})
            await bus.publish(event)

        await asyncio.sleep(0.2)
        await bus.stop()
        assert bus.event_count == 5

    @pytest.mark.asyncio
    async def test_start_twice_is_safe(self) -> None:
        bus = EventBus()
        await bus.start()
        await bus.start()  # Should warn but not crash
        await bus.stop()

    @pytest.mark.asyncio
    async def test_stop_without_start_is_safe(self) -> None:
        bus = EventBus()
        await bus.stop()  # Should not raise
