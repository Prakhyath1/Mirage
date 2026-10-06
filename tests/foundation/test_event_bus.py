"""Tests for the in-process async event bus: publish/subscribe,
error isolation between handlers, unsubscribe, recorder helper."""
import pytest

from app.events.bus import EventBus, EventRecorder
from app.models import EventType, SecurityEvent, Severity


def _event(session_id="sess_x", event_type="session_created"):
    return SecurityEvent.new(
        session_id=session_id,
        event_type=event_type,
        severity=Severity.INFO,
        source="test",
        payload={"k": "v"},
    )


class TestPubSub:
    async def test_publish_reaches_all_subscribers(self):
        bus = EventBus()
        seen_a, seen_b = [], []
        bus.subscribe(_recorder(seen_a))
        bus.subscribe(_recorder(seen_b))
        await bus.publish(_event())
        assert len(seen_a) == 1
        assert len(seen_b) == 1

    async def test_multiple_events_in_order(self):
        bus = EventBus()
        seen = []
        bus.subscribe(_recorder(seen))
        await bus.publish(_event(event_type="session_created"))
        await bus.publish(_event(event_type="command_submitted"))
        assert [e.event_type for e in seen] == [
            "session_created", "command_submitted"
        ]

    async def test_unsubscribe_stops_delivery(self):
        bus = EventBus()
        seen = []
        handler = _recorder(seen)
        bus.subscribe(handler)
        bus.unsubscribe(handler)
        await bus.publish(_event())
        assert seen == []
        assert bus.subscriber_count == 0


class TestErrorIsolation:
    async def test_failing_handler_does_not_break_others(self):
        bus = EventBus()
        seen = []

        async def bad(_: SecurityEvent) -> None:
            raise RuntimeError("boom")

        bus.subscribe(bad)
        bus.subscribe(_recorder(seen))
        # publish must not raise despite the broken handler
        await bus.publish(_event())
        assert len(seen) == 1

    async def test_all_handlers_failing_still_returns(self):
        bus = EventBus()

        async def bad(_: SecurityEvent) -> None:
            raise ValueError("nope")

        bus.subscribe(bad)
        bus.subscribe(bad)
        await bus.publish(_event())  # no exception escapes the bus


class TestLifecycle:
    async def test_publish_after_close_is_silent_noop(self):
        bus = EventBus()
        seen = []
        bus.subscribe(_recorder(seen))
        bus.close()
        # A closed bus drops events quietly — no subscriber, no raise.
        await bus.publish(_event())
        assert seen == []

    async def test_start_close_idempotent(self):
        bus = EventBus()
        bus.close()
        bus.close()  # second close is a no-op
        assert not bus.running

    async def test_publish_many(self):
        bus = EventBus()
        seen = []
        bus.subscribe(_recorder(seen))
        await bus.publish_many([_event(), _event(), _event()])
        assert len(seen) == 3

    async def test_stats_shape(self):
        bus = EventBus()
        bus.subscribe(_recorder([]))
        stats = bus.stats
        assert stats["subscribers"] == 1


def _recorder(sink: list) -> "EventRecorder":
    rec = EventRecorder()
    original = rec.__call__

    async def wrapped(event: SecurityEvent) -> None:
        sink.append(event)
        await original(event)

    wrapped.__name__ = "wrapped_recorder"
    return wrapped  # type: ignore[return-value]
