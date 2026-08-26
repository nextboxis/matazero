"""Analyzer registry."""

from __future__ import annotations
from typing import Dict, List, Optional
from imgint.core.analyzer.base import Analyzer


class AnalyzerRegistry:
    """Maintains registered forensic analyzers."""

    def __init__(self) -> None:
        self._analyzers: Dict[str, Analyzer] = {}

    def register(self, analyzer: Analyzer) -> None:
        self._analyzers[analyzer.id] = analyzer

    def get_analyzer(self, analyzer_id: str) -> Optional[Analyzer]:
        return self._analyzers.get(analyzer_id)

    def get_analyzers_for_tier(self, tier: int) -> List[Analyzer]:
        return [a for a in self._analyzers.values() if a.tier == tier]

    def get_all_analyzers(self) -> List[Analyzer]:
        return list(self._analyzers.values())
