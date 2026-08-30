"""Forensic event bus supporting synchronous priority-ordered pub-sub."""

from __future__ import annotations
import logging
from typing import Any, Callable, Dict, List, Type, TypeVar

from imgint.core.event.events import ForensicEvent

T = TypeVar("T", bound=ForensicEvent)
HandlerFunc = Callable[[Any], None]


class ForensicEventBus:
    """Central decoupled pub-sub dispatcher for forensic lifecycle events."""

    _instance: Optional[ForensicEventBus] = None

    def __init__(self) -> None:
        self._subscribers: Dict[Type[ForensicEvent], List[Tuple[int, HandlerFunc]]] = {}

    @classmethod
    def get_default(cls) -> ForensicEventBus:
        if cls._instance is None:
            cls._instance = ForensicEventBus()
        return cls._instance

    def subscribe(self, event_cls: Type[T], handler: Callable[[T], None], priority: int = 100) -> None:
        """Subscribes a handler to a specific event class. Lower priority number executes first."""
        if event_cls not in self._subscribers:
            self._subscribers[event_cls] = []
        self._subscribers[event_cls].append((priority, handler))
        self._subscribers[event_cls].sort(key=lambda item: item[0])

    def publish(self, event: ForensicEvent) -> None:
        """Dispatches an event to all registered handlers for the event class and its parent classes."""
        for event_cls, handlers in self._subscribers.items():
            if isinstance(event, event_cls):
                for _, handler in handlers:
                    try:
                        handler(event)
                    except Exception as e:
                        logging.getLogger("matazero.event").error(f"Error executing event handler {handler}: {e}")

    def clear(self) -> None:
        """Clears all registered handlers."""
        self._subscribers.clear()
