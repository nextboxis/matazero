"""Abstract base class for external forensic skills and plugins."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

from imgint.core.analyzer.base import AnalysisContext
from imgint.core.model.finding import Finding
from imgint.core.model.record import Diagnostic


class ForensicSkill(ABC):
    """Base class for dynamically loadable forensic skills and plugins."""

    @property
    @abstractmethod
    def id(self) -> str:
        """Unique skill identifier (e.g. 'custom_drone_telemetry')."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable skill name."""
        ...

    @property
    def version(self) -> str:
        """Semantic version of the skill."""
        return "1.0.0"

    @property
    def description(self) -> str:
        """Description of the forensic analysis performed by this skill."""
        return ""

    @property
    def target_tier(self) -> int:
        """Pipeline extraction tier where this skill operates (1-7)."""
        return 6

    @property
    def supported_formats(self) -> List[str]:
        """List of supported image container formats (e.g. ['JPEG', 'PNG', 'TIFF'] or ['*'])."""
        return ["*"]

    @property
    def requires_decode(self) -> bool:
        """Whether this skill requires sandboxed pixel decoding."""
        return False

    @abstractmethod
    def analyze(self, ctx: AnalysisContext) -> Tuple[List[Finding], List[Diagnostic]]:
        """Executes the skill analysis logic over the provided context."""
        ...
