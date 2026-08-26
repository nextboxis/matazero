"""Abstract analyzer interface and analysis context."""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from imgint.core.model.finding import Finding
from imgint.core.model.record import StructuralUnit, MetadataBlock, Field, Diagnostic
from imgint.core.source.reader import BoundedReader
from imgint.core.governance.scope import AuthorizationScope


@dataclass
class AnalysisContext:
    file_path: Path
    reader: BoundedReader
    format_name: str
    structural_units: List[StructuralUnit] = field(default_factory=list)
    metadata_blocks: List[MetadataBlock] = field(default_factory=list)
    fields: List[Field] = field(default_factory=list)
    existing_findings: List[Finding] = field(default_factory=list)
    diagnostics: List[Diagnostic] = field(default_factory=list)
    scope: Optional[AuthorizationScope] = None
    allow_network: bool = False
    enable_ela: bool = False

    def get_field_value(self, name: str) -> Optional[Any]:
        for f in self.fields:
            if f.name.lower() == name.lower() or f.name.endswith(f":{name}"):
                return f.value
        return None

    def get_finding(self, name: str) -> Optional[Finding]:
        for f in self.existing_findings:
            if f.name.lower() == name.lower():
                return f
        return None


class Analyzer(ABC):
    """Abstract interface for Tier 4-7 analytical passes."""

    @property
    @abstractmethod
    def id(self) -> str:
        pass

    @property
    @abstractmethod
    def tier(self) -> int:
        pass

    @property
    @abstractmethod
    def requires_decode(self) -> bool:
        """If true, this analyzer MUST be executed inside the sandbox child process per ADR-004."""
        pass

    @abstractmethod
    def analyze(self, ctx: AnalysisContext) -> Tuple[List[Finding], List[Diagnostic]]:
        pass
