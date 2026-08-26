"""Container reader registry."""

from __future__ import annotations
from typing import Dict, List, Optional
from imgint.core.container.base import ContainerReader


class ContainerRegistry:
    """Maintains registered container format readers."""

    def __init__(self) -> None:
        self._readers: List[ContainerReader] = []

    def register(self, reader: ContainerReader) -> None:
        self._readers.append(reader)

    def get_reader(self, format_name: str) -> Optional[ContainerReader]:
        for r in self._readers:
            if r.handles(format_name):
                return r
        return None
