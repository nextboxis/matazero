"""Tests for Lossless Metadata Sanitizer (JPEG, PNG, WebP)."""

import pytest
from pathlib import Path
from PIL import Image, PngImagePlugin
from imgint.core.clean.cleaner import MetadataCleaner


def test_jpeg_clean(tmp_path):
    p = tmp_path / "dirty.jpg"
    out_p = tmp_path / "cleaned.jpg"

    img = Image.new("RGB", (64, 64), color="yellow")
    # Save with EXIF info
    exif = img.getexif()
    exif[0x010E] = "Sensitive Secret Comment"
    img.save(p, "JPEG", exif=exif)

    cleaned_bytes, orig_sz, clean_sz = MetadataCleaner.clean_file(p, out_p)
    assert out_p.exists()
    assert b"Sensitive Secret Comment" not in cleaned_bytes
    assert clean_sz <= orig_sz

    # Verify image still loads correctly
    loaded = Image.open(out_p)
    assert loaded.size == (64, 64)


def test_png_clean(tmp_path):
    p = tmp_path / "dirty.png"
    out_p = tmp_path / "cleaned.png"

    img = Image.new("RGB", (64, 64), color="green")
    pnginfo = PngImagePlugin.PngInfo()
    pnginfo.add_text("SecretKey", "TopSecret12345")
    img.save(p, "PNG", pnginfo=pnginfo)

    cleaned_bytes, orig_sz, clean_sz = MetadataCleaner.clean_file(p, out_p)
    assert out_p.exists()
    assert b"TopSecret12345" not in cleaned_bytes
    assert clean_sz < orig_sz

    loaded = Image.open(out_p)
    assert loaded.size == (64, 64)


def test_webp_clean(tmp_path):
    p = tmp_path / "dirty.webp"
    out_p = tmp_path / "cleaned.webp"

    img = Image.new("RGB", (64, 64), color="purple")
    exif = img.getexif()
    exif[0x010E] = "WebP Secret Note"
    img.save(p, "WEBP", exif=exif)

    cleaned_bytes, orig_sz, clean_sz = MetadataCleaner.clean_file(p, out_p)
    assert out_p.exists()
    assert b"WebP Secret Note" not in cleaned_bytes

    loaded = Image.open(out_p)
    assert loaded.size == (64, 64)
