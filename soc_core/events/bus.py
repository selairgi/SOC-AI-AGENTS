"""
Minimal in-memory event bus for SOC agent communication.

This module provides a simple synchronous publish/subscribe event bus
with no external dependencies. Events are dispatched immediately to
all registered handlers.

Usage:
    bus = EventBus()
    bus.subscribe("AlertDetected", my_handler)
    bus.publish("AlertDetected", {"event_id": "...", "payload": {...}})
"""

from typing import Callable, Dict, List, Any
from collections import defaultdict


class EventBus:
    """
    A minimal synchronous in-memory event bus.

    Supports multiple handlers per event type. Handlers are called
    synchronously in the order they were registered.
    """

    def __init__(self) -> None:
        """Initialize the event bus with empty handler registry."""
        self._handlers: Dict[str, List[Callable[[dict], None]]] = defaultdict(list)

    def subscribe(self, event_type: str, handler: Callable[[dict], None]) -> None:
        """
        Register a handler for a specific event type.

        Args:
            event_type: The type of event to subscribe to (e.g., "AlertDetected")
            handler: A callable that accepts a dict (the event) as its argument

        Raises:
            TypeError: If handler is not callable
        """
        if not callable(handler):
            raise TypeError(f"Handler must be callable, got {type(handler).__name__}")

        self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: str, handler: Callable[[dict], None]) -> bool:
        """
        Remove a handler from a specific event type.

        Args:
            event_type: The type of event to unsubscribe from
            handler: The handler to remove

        Returns:
            True if handler was removed, False if it wasn't registered
        """
        if event_type in self._handlers and handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)
            return True
        return False

    def publish(self, event_type: str, event: dict) -> int:
        """
        Publish an event to all registered handlers.

        Handlers are called synchronously in registration order.
        If a handler raises an exception, it propagates immediately
        and subsequent handlers are not called.

        Args:
            event_type: The type of event being published
            event: The event data as a dictionary

        Returns:
            The number of handlers that were called

        Raises:
            TypeError: If event is not a dict
        """
        if not isinstance(event, dict):
            raise TypeError(f"Event must be a dict, got {type(event).__name__}")

        handlers = self._handlers.get(event_type, [])
        for handler in handlers:
            handler(event)

        return len(handlers)

    def has_subscribers(self, event_type: str) -> bool:
        """
        Check if an event type has any registered handlers.

        Args:
            event_type: The event type to check

        Returns:
            True if at least one handler is registered
        """
        return len(self._handlers.get(event_type, [])) > 0

    def subscriber_count(self, event_type: str) -> int:
        """
        Get the number of handlers registered for an event type.

        Args:
            event_type: The event type to check

        Returns:
            Number of registered handlers
        """
        return len(self._handlers.get(event_type, []))

    def clear(self, event_type: str = None) -> None:
        """
        Remove all handlers for a specific event type, or all handlers.

        Args:
            event_type: The event type to clear. If None, clears all handlers.
        """
        if event_type is None:
            self._handlers.clear()
        elif event_type in self._handlers:
            del self._handlers[event_type]
