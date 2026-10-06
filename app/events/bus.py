"""Asynchronous in-process event bus.

The bus is the only sanctioned way for components to emit and consume
runtime events. Design constraints:

- Handlers are async callables taking a :class:`app.models.SecurityEvent`.
- A raising handler is isolated: the failure is logged, other subscribers
  still receive the event, and the publisher is never affected.
- Events are treated as immutable after publication (they are frozen
  dataclasses; handlers must not mutate — copies are cheap to make).
- Publishing is serial in subscription order, giving deterministic
  ordering for local, in-process use.

The public surface (:class:`EventBus` and the :class:`EventPublisher` /
:class:`EventHandler` protocols) is deliberately small so a Redis/ZeroMQ
backed implementation can replace it later without touching consumers.
"""
from __future__ import annotations

import asyncio
from typing import Protocol, runtime_checkable

from ..logger import get_logger
from ..models import SecurityEvent

log = get_logger("events.bus")


@runtime_checkable
class EventHandler(Protocol):
    async def __call__(self, event: SecurityEvent) -> None:
        """Process one event. Must not raise for expected conditions."""
        ...


@runtime_checkable
class EventPublisher(Protocol):
    async def publish(self, event: SecurityEvent) -> None:
        """Dispatch ``event`` to all current subscribers."""
        ...


class EventBus:
    """In-process async pub/sub with handler error isolation.

    Thread-safety note: subscribe/unsubscribe are synchronous and should
    happen on the event loop (or before the runtime starts). Publishing
    schedules nothing: it awaits handlers directly, in subscription order.
    """

    def __init__(self, name: str = "default") -> None:
        self._name = name
        self._subscribers: list[EventHandler] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed = False
        self._published_count = 0
        self._handler_errors = 0

    # -- subscription management ------------------------------------

    def subscribe(self, handler: EventHandler) -> None:
        if handler not in self._subscribers:
            self._subscribers.append(handler)
            log.debug("subscriber added", bus=self._name, total=len(self._subscribers))

    def unsubscribe(self, handler: EventHandler) -> None:
        try:
            self._subscribers.remove(handler)
            log.debug("subscriber removed", bus=self._name, total=len(self._subscribers))
        except ValueError:
            pass

    # -- publishing -------------------------------------------------

    async def publish(self, event: SecurityEvent) -> None:
        """Dispatch ``event`` to every subscriber, isolating failures."""
        if self._closed:
            return
        self._published_count += 1
        for handler in list(self._subscribers):
            try:
                await handler(event)
            except Exception:
                self._handler_errors += 1
                log.exception(
                    "event handler failed; continuing with remaining subscribers",
                    bus=self._name,
                    event_id=event.event_id,
                    event_type=event.event_type,
                    session_id=event.session_id,
                    handler=repr(handler),
                )

    async def publish_many(self, events: list[SecurityEvent]) -> None:
        for event in events:
            await self.publish(event)

    # -- lifecycle --------------------------------------------------

    def close(self) -> None:
        """Stop accepting new events. Subscribers are cleared."""
        self._closed = True
        self._subscribers.clear()

    @property
    def running(self) -> bool:
        return not self._closed

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    @property
    def stats(self) -> dict:
        return {
            "name": self._name,
            "running": self.running,
            "subscribers": len(self._subscribers),
            "published": self._published_count,
            "handler_errors": self._handler_errors,
        }


class EventRecorder:
    """Test/observer helper: records every event it receives.

    T4 can use this to expose recent events without polling the
    database, and tests use it to assert on emission behaviour.
    """

    def __init__(self, limit: int = 1000) -> None:
        self.events: list[SecurityEvent] = []
        self._limit = limit

    async def __call__(self, event: SecurityEvent) -> None:
        self.events.append(event)
        if len(self.events) > self._limit:
            self.events = self.events[-self._limit:]

    def by_type(self, event_type: str) -> list[SecurityEvent]:
        return [e for e in self.events if e.event_type == event_type]

    def by_session(self, session_id: str) -> list[SecurityEvent]:
        return [e for e in self.events if e.session_id == session_id]

    def clear(self) -> None:
        self.events.clear()
