"""Standard block parser registry."""

from __future__ import annotations
from typing import List, Optional
from imgint.core.standard.base import BlockParser


class StandardRegistry:
    """Maintains registered metadata standard parsers."""

    def __init__(self) -> None:
        self._parsers: List[BlockParser] = []

    def register(self, parser: BlockParser) -> None:
        self._parsers.append(parser)

    def get_parser(self, kind: str) -> Optional[BlockParser]:
        for p in self._parsers:
            if p.handles(kind):
                return p
        return None
