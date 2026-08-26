"""Finding, Confidence, and Provenance models."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Confidence(str, Enum):
    OBSERVED = "observed"
    DERIVED = "derived"
    INDICATIVE = "indicative"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Provenance:
    source_layer: str  # e.g., "container", "standard", "fingerprint", "artefact", "analyzer"
    extractor: str     # e.g., "jpeg_dqt", "exif_gps", "offline_geocoder"
    offset: Optional[int] = None
    length: Optional[int] = None
    standard: Optional[str] = None
    tag_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "source_layer": self.source_layer,
            "extractor": self.extractor,
        }
        if self.offset is not None:
            d["offset"] = self.offset
        if self.length is not None:
            d["length"] = self.length
        if self.standard is not None:
            d["standard"] = self.standard
        if self.tag_id is not None:
            d["tag_id"] = self.tag_id
        return d


@dataclass
class Finding:
    """An evidence-grade assertion extracted or derived from an image."""
    name: str
    value: Any
    tier: int
    extractor: str
    confidence: Confidence
    caveat: Optional[str] = None
    provenance: Optional[Provenance] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Enforce ADR-008: Confidence and caveat as required fields
        if not isinstance(self.confidence, Confidence):
            if isinstance(self.confidence, str):
                try:
                    self.confidence = Confidence(self.confidence.lower())
                except ValueError:
                    raise ValueError(
                        f"Invalid confidence '{self.confidence}'. Must be one of: "
                        f"{[c.value for c in Confidence]}"
                    )
            else:
                raise TypeError(f"confidence must be a Confidence enum instance, got {type(self.confidence)}")

        if self.confidence in (Confidence.DERIVED, Confidence.INDICATIVE, Confidence.INCONCLUSIVE):
            if not self.caveat or not self.caveat.strip():
                raise ValueError(
                    f"Finding '{self.name}' with confidence '{self.confidence.value}' "
                    f"MUST have a non-empty caveat describing uncertainty and false-positive context."
                )

        if not (1 <= self.tier <= 7):
            raise ValueError(f"Tier must be between 1 and 7, got {self.tier}")

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "name": self.name,
            "value": self.value,
            "tier": self.tier,
            "extractor": self.extractor,
            "confidence": self.confidence.value,
        }
        if self.caveat is not None:
            res["caveat"] = self.caveat
        if self.provenance is not None:
            res["provenance"] = self.provenance.to_dict()
        if self.metadata:
            res["metadata"] = self.metadata
        return res
