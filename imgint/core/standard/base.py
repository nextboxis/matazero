"""Abstract standard parser interface and standard models."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Tuple
from imgint.core.model.record import MetadataBlock, Field, Diagnostic
from imgint.core.model.finding import Finding


class BlockParser(ABC):
    """Abstract interface for metadata standard parsers (EXIF, XMP, IPTC, ICC, etc.)."""

    @abstractmethod
    def handles(self, kind: str) -> bool:
        pass

    @abstractmethod
    def parse(
        self, block: MetadataBlock
    ) -> Tuple[List[Field], List[Finding], List[Diagnostic]]:
        """Parses raw metadata block into structured Fields, Findings, and Diagnostics."""
        pass
