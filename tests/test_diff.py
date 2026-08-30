"""Tests for Forensic Comparator and Differential Analysis."""

import pytest
from pathlib import Path
from PIL import Image
from imgint.core.diff import ForensicComparator


@pytest.fixture
def identical_images(tmp_path):
    p1 = tmp_path / "img1.png"
    p2 = tmp_path / "img2.png"
    img = Image.new("RGB", (32, 32), color="green")
    img.save(p1, "PNG")
    img.save(p2, "PNG")
    return p1, p2


@pytest.fixture
def altered_images(tmp_path):
    p1 = tmp_path / "base.jpg"
    p2 = tmp_path / "altered.jpg"
    img1 = Image.new("RGB", (50, 50), color="white")
    img1.save(p1, "JPEG", quality=95)
    
    img2 = Image.new("RGB", (50, 50), color="white")
    # Draw red rectangle in center
    for x in range(20, 30):
        for y in range(20, 30):
            img2.putpixel((x, y), (255, 0, 0))
    img2.save(p2, "JPEG", quality=95)
    return p1, p2


def test_identical_images_diff(identical_images):
    p1, p2 = identical_images
    res = ForensicComparator.compare(p1, p2)
    assert res.sha256_match is True
    assert res.relationship_verdict == "EXACT_BITWISE_MATCH"
    assert res.pixel_diff["altered_pixels_count"] == 0


def test_altered_pixels_diff(altered_images):
    p1, p2 = altered_images
    res = ForensicComparator.compare(p1, p2)
    assert res.sha256_match is False
    assert res.pixel_diff is not None
    assert res.pixel_diff["altered_pixels_count"] > 0
    assert "TAMPERING" in res.relationship_verdict or "ALTERED" in res.relationship_verdict or "LOCALIZED" in res.relationship_verdict
