"""Embedded artefact extraction modules."""

from imgint.core.artefact.thumbnail import ThumbnailExtractor, ExtractedThumbnail
from imgint.core.artefact.mpf import MpfExtractor, MpfImage
from imgint.core.artefact.trailing import TrailingDataExtractor, TrailingDataInfo
from imgint.core.artefact.preview import PreviewExtractor
from imgint.core.artefact.anomalies import ContainerAnomalyDetector

__all__ = [
    "ThumbnailExtractor",
    "ExtractedThumbnail",
    "MpfExtractor",
    "MpfImage",
    "TrailingDataExtractor",
    "TrailingDataInfo",
    "PreviewExtractor",
    "ContainerAnomalyDetector",
]
