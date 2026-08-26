"""Embedded EXIF thumbnail extractor and divergence checker per SRD FR-4.1 - FR-4.3."""

from __future__ import annotations
import struct
from dataclasses import dataclass
from typing import Optional, Tuple
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import MetadataBlock


@dataclass
class ExtractedThumbnail:
    data: bytes
    offset: int
    length: int
    format_type: str = "JPEG"
    width: Optional[int] = None
    height: Optional[int] = None


class ThumbnailExtractor:
    """Extracts embedded EXIF thumbnail from IFD1."""

    @staticmethod
    def extract_from_exif_block(block: MetadataBlock) -> Optional[ExtractedThumbnail]:
        data = block.raw_bytes
        size = len(data)
        if size < 8:
            return None

        endian_str = data[:2]
        if endian_str == b"II":
            endian = "<"
        elif endian_str == b"MM":
            endian = ">"
        else:
            return None

        first_ifd_offset = struct.unpack(f"{endian}I", data[4:8])[0]
        if first_ifd_offset <= 0 or first_ifd_offset + 2 > size:
            return None

        # Find IFD1 by skipping IFD0 entries
        entry_count = struct.unpack(f"{endian}H", data[first_ifd_offset : first_ifd_offset + 2])[0]
        next_ptr_offset = first_ifd_offset + 2 + entry_count * 12

        if next_ptr_offset + 4 > size:
            return None

        ifd1_offset = struct.unpack(f"{endian}I", data[next_ptr_offset : next_ptr_offset + 4])[0]
        if ifd1_offset <= 0 or ifd1_offset + 2 > size:
            return None

        # Parse IFD1
        ifd1_count = struct.unpack(f"{endian}H", data[ifd1_offset : ifd1_offset + 2])[0]
        curr = ifd1_offset + 2

        thumb_offset: Optional[int] = None
        thumb_len: Optional[int] = None

        for _ in range(ifd1_count):
            if curr + 12 > size:
                break
            tag_id, field_type, count, val_or_offset = struct.unpack(
                f"{endian}HHI I", data[curr : curr + 12]
            )
            curr += 12

            if tag_id == 0x0201:  # JPEGInterchangeFormat
                thumb_offset = val_or_offset
            elif tag_id == 0x0202:  # JPEGInterchangeFormatLength
                thumb_len = val_or_offset

        if thumb_offset is not None and thumb_len is not None:
            if thumb_offset + thumb_len <= size:
                thumb_bytes = data[thumb_offset : thumb_offset + thumb_len]
                return ExtractedThumbnail(
                    data=thumb_bytes,
                    offset=block.offset + thumb_offset,
                    length=thumb_len,
                    format_type="JPEG",
                )

        return None
