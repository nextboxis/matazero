"""Carver for extracting embedded motion video streams."""

from __future__ import annotations
from pathlib import Path
from typing import Optional

from imgint.core.motion.detector import MotionPhotoDetector, MotionPhotoInfo
from imgint.core.source.reader import BoundedReader


class MotionPhotoCarver:
    """Carves embedded MP4/HEVC video streams from motion photos."""

    @classmethod
    def carve(
        cls,
        target_path: str | Path,
        output_dir: Optional[str | Path] = None,
        output_file: Optional[str | Path] = None,
    ) -> MotionPhotoInfo:
        p = Path(target_path)
        info = MotionPhotoDetector.detect(p)

        if not info.is_motion_photo or info.video_offset is None or info.video_size_bytes is None:
            return info

        reader = BoundedReader(p)
        video_bytes = reader.read_bytes(info.video_offset, info.video_size_bytes)

        if output_file:
            dest_path = Path(output_file)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            out_folder = Path(output_dir or "./carved_motion")
            out_folder.mkdir(parents=True, exist_ok=True)
            ext = ".mov" if info.video_codec_brand == "qt  " else ".mp4"
            dest_path = out_folder / f"{p.stem}_motion{ext}"

        dest_path.write_bytes(video_bytes)
        info.carved_path = str(dest_path)
        return info
