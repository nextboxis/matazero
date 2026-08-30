"""Tests for Motion and Live Photo detector and carver."""

import pytest
import struct
from pathlib import Path
from PIL import Image
from imgint.core.motion import MotionPhotoDetector, MotionPhotoCarver


@pytest.fixture
def mock_motion_photo(tmp_path):
    # Create a JPEG with an embedded MP4 stream
    jpg_path = tmp_path / "motion_test.jpg"
    img = Image.new("RGB", (64, 64), color="cyan")
    img.save(jpg_path, "JPEG", quality=90)

    # Append mock MP4 data: box_size (24 bytes) + b"ftypmp42" + 16 bytes payload
    mp4_data = bytearray()
    mp4_data.extend(struct.pack(">I", 24))
    mp4_data.extend(b"ftypmp42")
    mp4_data.extend(b"\x00" * 12)
    # Add dummy video track
    mp4_data.extend(b"\x00\x00\x00\x10mdat12345678")

    with open(jpg_path, "ab") as f:
        f.write(mp4_data)

    return jpg_path


def test_motion_photo_detection(mock_motion_photo):
    info = MotionPhotoDetector.detect(mock_motion_photo)
    assert info.is_motion_photo is True
    assert info.video_offset is not None
    assert info.video_size_bytes is not None
    assert info.video_size_bytes > 0
    assert info.video_codec_brand == "mp42"


def test_motion_photo_carver(mock_motion_photo, tmp_path):
    out_dir = tmp_path / "carved_videos"
    info = MotionPhotoCarver.carve(mock_motion_photo, output_dir=out_dir)
    assert info.carved_path is not None
    assert Path(info.carved_path).exists()
    assert Path(info.carved_path).stat().st_size > 0
