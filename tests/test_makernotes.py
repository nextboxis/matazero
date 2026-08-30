"""Tests for Camera MakerNotes Decoders (Nikon, Apple, Canon, Sony)."""

import pytest
import struct
from pathlib import Path
from imgint.core.standard.exif import ExifParser
from imgint.core.model.record import MetadataBlock


def test_nikon_makernote_decoding():
    # Build Nikon MakerNote payload
    nikon_payload = bytearray(b"Nikon\x00\x02\x00\x00\x00")
    # Sub IFD: 2 entries, Big Endian
    nikon_payload.extend(struct.pack(">H", 2))
    # Entry 1: tag 0x00A7 (NikonShutterCount), type LONG (4), count 1, val 14520
    nikon_payload.extend(struct.pack(">HHI I", 0x00A7, 4, 1, 14520))
    # Entry 2: tag 0x001D (NikonSerialNumber), type ASCII (2), count 8, val offset 38
    nikon_payload.extend(struct.pack(">HHI I", 0x001D, 2, 8, 38))
    nikon_payload.extend(b"6045891\x00")

    # Wrap in standard EXIF block:
    # TIFF header (8 bytes) + IFD0 (tag 0x927C MakerNote) + next IFD pointer (4 bytes) = 26 bytes
    exif_data = bytearray(b"Exif\x00\x00MM\x00*\x00\x00\x00\x08")
    exif_data.extend(struct.pack(">H", 1))  # 1 entry in IFD0
    exif_data.extend(struct.pack(">HHI I", 0x927C, 7, len(nikon_payload), 26))  # val offset in data is 26
    exif_data.extend(struct.pack(">I", 0))  # next IFD pointer
    exif_data.extend(nikon_payload)

    block = MetadataBlock(kind="EXIF", offset=100, length=len(exif_data), raw_bytes=bytes(exif_data))
    parser = ExifParser()
    fields, findings, diagnostics = parser.parse(block)

    shutter_field = next((f for f in fields if "NikonShutterCount" in f.name), None)
    assert shutter_field is not None
    assert shutter_field.value == 14520


def test_apple_makernote_decoding():
    apple_payload = bytearray(b"Apple iOS\x00\x00\x01MM")
    # 1 entry: tag 0x000E = AppleHDRImageType (value 3)
    apple_payload.extend(struct.pack(">H", 1))
    apple_payload.extend(struct.pack(">HHI I", 0x000E, 3, 1, 3))

    exif_data = bytearray(b"Exif\x00\x00MM\x00*\x00\x00\x00\x08")
    exif_data.extend(struct.pack(">H", 1))
    exif_data.extend(struct.pack(">HHI I", 0x927C, 7, len(apple_payload), 26))
    exif_data.extend(struct.pack(">I", 0))
    exif_data.extend(apple_payload)

    block = MetadataBlock(kind="EXIF", offset=0, length=len(exif_data), raw_bytes=bytes(exif_data))
    parser = ExifParser()
    fields, findings, diagnostics = parser.parse(block)

    hdr_field = next((f for f in fields if "AppleHDRImageType" in f.name), None)
    assert hdr_field is not None
    assert hdr_field.value == 3
