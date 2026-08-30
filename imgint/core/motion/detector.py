"""Motion photo and embedded video stream detector for Samsung, Google Pixel, and Apple Live Photos."""

from __future__ import annotations
import re
import struct
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from imgint.core.source.reader import BoundedReader


@dataclass
class MotionPhotoInfo:
    file_name: str
    file_path: str
    is_motion_photo: bool
    motion_type: str  # "SAMSUNG_MOTION_PHOTO", "GOOGLE_PIXEL_MICROVIDEO", "GENERIC_EMBEDDED_MP4", "APPLE_LIVE_PHOTO_TRACK", "NONE"
    video_offset: Optional[int] = None
    video_size_bytes: Optional[int] = None
    presentation_timestamp_us: Optional[int] = None
    xmp_attributes: Dict[str, str] = field(default_factory=dict)
    video_codec_brand: Optional[str] = None
    carved_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MotionPhotoDetector:
    """Detects embedded video streams inside JPEG and HEIC images."""

    @classmethod
    def detect(cls, target_path: str | Path) -> MotionPhotoInfo:
        p = Path(target_path)
        reader = BoundedReader(p)
        total_size = reader.size

        # Default info
        info = MotionPhotoInfo(
            file_name=p.name,
            file_path=str(p),
            is_motion_photo=False,
            motion_type="NONE",
        )

        if total_size < 32:
            return info

        # Read first 1MB and last 2MB for signatures
        header_sample = reader.read_bytes(0, min(total_size, 512 * 1024))
        trailer_sample_len = min(total_size, 1024 * 1024)
        trailer_offset = total_size - trailer_sample_len
        trailer_sample = reader.read_bytes(trailer_offset, trailer_sample_len)

        # 1. Check for XMP GCamera:MicroVideo / MotionPhoto attributes in header/full
        all_text = (header_sample + trailer_sample).decode("latin-1", errors="ignore")

        # Regex search for XMP MicroVideo attributes
        is_mv = re.search(r'GCamera:MicroVideo\s*=\s*["\']?1["\']?', all_text, re.IGNORECASE) or \
                re.search(r'MotionPhoto\s*=\s*["\']?1["\']?', all_text, re.IGNORECASE)
        
        offset_match = re.search(r'GCamera:MicroVideoOffset\s*=\s*["\']?(\d+)["\']?', all_text, re.IGNORECASE) or \
                       re.search(r'MotionPhotoOffset\s*=\s*["\']?(\d+)["\']?', all_text, re.IGNORECASE) or \
                       re.search(r'Item:Length\s*=\s*["\']?(\d+)["\']?', all_text, re.IGNORECASE)

        pts_match = re.search(r'MotionPhotoPresentationTimestampUs\s*=\s*["\']?(\d+)["\']?', all_text, re.IGNORECASE) or \
                    re.search(r'GCamera:MicroVideoPresentationTimestampUs\s*=\s*["\']?(\d+)["\']?', all_text, re.IGNORECASE)

        xmp_attrs = {}
        if is_mv:
            xmp_attrs["MotionPhoto"] = "1"
        if offset_match:
            xmp_attrs["Offset"] = offset_match.group(1)
        if pts_match:
            xmp_attrs["PresentationTimestampUs"] = pts_match.group(1)
            info.presentation_timestamp_us = int(pts_match.group(1))

        # If XMP offset is specified (offset from EOF)
        if offset_match:
            mv_offset_from_eof = int(offset_match.group(1))
            if 0 < mv_offset_from_eof < total_size:
                vid_start = total_size - mv_offset_from_eof
                # Verify MP4 magic at vid_start
                if vid_start + 8 <= total_size:
                    box_tag = reader.read_bytes(vid_start + 4, 4)
                    if box_tag == b"ftyp":
                        brand = reader.read_bytes(vid_start + 8, 4).decode("ascii", errors="replace")
                        info.is_motion_photo = True
                        info.motion_type = "GOOGLE_PIXEL_MICROVIDEO" if "GCamera" in all_text else "SAMSUNG_MOTION_PHOTO"
                        info.video_offset = vid_start
                        info.video_size_bytes = mv_offset_from_eof
                        info.video_codec_brand = brand
                        info.xmp_attributes = xmp_attrs
                        return info

        # 2. Binary Scan for embedded 'ftyp' MP4 box beyond JPEG header
        # Scan full bytes for 'ftyp'
        raw_bytes = reader.get_all_bytes()
        ftyp_idx = 0
        while True:
            ftyp_pos = raw_bytes.find(b"ftyp", ftyp_idx)
            if ftyp_pos == -1:
                break
            if ftyp_pos >= 4:
                box_start = ftyp_pos - 4
                box_len = struct.unpack(">I", raw_bytes[box_start:box_start + 4])[0]
                if 8 <= box_len <= (total_size - box_start):
                    brand = raw_bytes[ftyp_pos + 4:ftyp_pos + 8].decode("ascii", errors="replace")
                    if brand.strip() in ("mp41", "mp42", "isom", "iso2", "avc1", "qt  ", "MSNV"):
                        info.is_motion_photo = True
                        info.motion_type = "GENERIC_EMBEDDED_MP4"
                        info.video_offset = box_start
                        info.video_size_bytes = total_size - box_start
                        info.video_codec_brand = brand
                        info.xmp_attributes = xmp_attrs
                        return info
            ftyp_idx = ftyp_pos + 4

        return info
