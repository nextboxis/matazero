"""Embedded preview image extractor for TIFF/RAW containers per SRD FR-4.6."""

from __future__ import annotations
from typing import List, Optional
from imgint.core.model.record import MetadataBlock


class PreviewExtractor:
    """Extracts full-resolution preview JPEGs embedded in RAW/TIFF containers."""

    @staticmethod
    def extract_preview(data: bytes) -> Optional[bytes]:
        # Search for embedded JPEG stream (FF D8 FF)
        soi_idx = data.find(b"\xFF\xD8\xFF", 8)  # Skip beginning if main file is JPEG
        if soi_idx != -1:
            eoi_idx = data.find(b"\xFF\xD9", soi_idx)
            if eoi_idx != -1:
                return data[soi_idx : eoi_idx + 2]
        return None
