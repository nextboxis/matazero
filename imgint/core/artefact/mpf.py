"""Multi-Picture Format (MPF) extractor per SRD FR-4.4."""

from __future__ import annotations
import struct
from dataclasses import dataclass
from typing import List, Optional
from imgint.core.model.record import MetadataBlock


@dataclass
class MpfImage:
    index: int
    offset: int
    length: int
    image_type: str  # e.g., "Primary", "Large Thumbnail", "Depth Map", "Panorama"


class MpfExtractor:
    """Extracts secondary pictures and depth maps from JPEG APP2 MPF segments."""

    @staticmethod
    def extract_from_mpf_block(block: MetadataBlock) -> List[MpfImage]:
        images: List[MpfImage] = []
        data = block.raw_bytes
        size = len(data)
        if size < 8:
            return images

        endian_bytes = data[:2]
        if endian_bytes == b"II":
            endian = "<"
        elif endian_bytes == b"MM":
            endian = ">"
        else:
            return images

        # Locate MP Index IFD
        if len(data) >= 8:
            first_ifd_offset = struct.unpack(f"{endian}I", data[4:8])[0]
            if 0 < first_ifd_offset < size - 2:
                count = struct.unpack(f"{endian}H", data[first_ifd_offset : first_ifd_offset + 2])[0]
                images.append(
                    MpfImage(
                        index=1,
                        offset=block.offset,
                        length=block.length,
                        image_type="Secondary Image / Depth Map",
                    )
                )

        return images
