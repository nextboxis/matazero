"""Forensic analyzers and registry."""

from imgint.core.analyzer.base import Analyzer, AnalysisContext
from imgint.core.analyzer.registry import AnalyzerRegistry
from imgint.core.analyzer.tier4_hash import HashingAnalyzer
from imgint.core.analyzer.tier5_geotime import GeoTimeAnalyzer
from imgint.core.analyzer.tier6_indicators import IndicatorsAnalyzer
from imgint.core.analyzer.tier7_content import ContentAnalyzer
from imgint.core.analyzer.ghost import JpegGhostDetector
from imgint.core.analyzer.cfa import CfaDemosaicAnalyzer
from imgint.core.analyzer.copymove import CopyMoveDetector


def create_default_analyzer_registry() -> AnalyzerRegistry:
    reg = AnalyzerRegistry()
    reg.register(HashingAnalyzer())
    reg.register(GeoTimeAnalyzer())
    reg.register(IndicatorsAnalyzer())
    reg.register(ContentAnalyzer())
    return reg


__all__ = [
    "Analyzer",
    "AnalysisContext",
    "AnalyzerRegistry",
    "HashingAnalyzer",
    "GeoTimeAnalyzer",
    "IndicatorsAnalyzer",
    "ContentAnalyzer",
    "JpegGhostDetector",
    "CfaDemosaicAnalyzer",
    "CopyMoveDetector",
    "create_default_analyzer_registry",
]
