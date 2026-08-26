"""Container segment and chunk ordering sequence generator per SRD FR-3.4."""

from __future__ import annotations
from typing import List
from imgint.core.model.record import StructuralUnit


class SegmentOrderExtractor:
    """Extracts and normalizes the ordered sequence of container units."""

    @staticmethod
    def extract_sequence(units: List[StructuralUnit]) -> List[str]:
        return [u.name for u in units if u.name != "TRAILING_DATA"]

    @staticmethod
    def to_string_sequence(units: List[StructuralUnit]) -> str:
        seq = SegmentOrderExtractor.extract_sequence(units)
        return " > ".join(seq)
