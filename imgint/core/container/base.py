"""Abstract base container reader interface and container models."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Tuple
from imgint.core.model.record import StructuralUnit, MetadataBlock, Diagnostic
from imgint.core.source.reader import BoundedReader


class ContainerReader(ABC):
    """Abstract interface for format-specific container parsers."""

    @abstractmethod
    def handles(self, format_name: str) -> bool:
        pass

    @abstractmethod
    def read(
        self, reader: BoundedReader
    ) -> Tuple[List[StructuralUnit], List[MetadataBlock], List[Diagnostic]]:
        """Walks container structures, extracting structural units, metadata blocks, and diagnostics."""
        pass
