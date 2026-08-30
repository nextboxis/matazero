"""Tests for hardened container and EXIF parsers."""

import pytest
import struct
from pathlib import Path
from imgint.core.source.reader import BoundedReader
from imgint.core.standard.exif import ExifParser
from imgint.core.container.bmff import BmffContainerReader
from imgint.core.container.tiff import TiffContainerReader
from imgint.core.model.record import MetadataBlock


def test_exif_circular_pointer_protection():
    # Build a malformed EXIF block where IFD0 points to IFD1 and IFD1 points back to IFD0
    # Header: II (Little-endian), 42 (magic), offset to IFD0 (8)
    # IFD0 at offset 8: count = 0, next IFD = 14 (IFD1)
    # IFD1 at offset 14: count = 0, next IFD = 8 (IFD0 -> Cycle!)
    data = bytearray(b"II\x2A\x00\x08\x00\x00\x00")
    # IFD0: 0 entries (2 bytes) + next_ifd = 14 (4 bytes)
    data.extend(struct.pack("<HI", 0, 14))
    # IFD1: 0 entries (2 bytes) + next_ifd = 8 (4 bytes -> back to IFD0)
    data.extend(struct.pack("<HI", 0, 8))

    block = MetadataBlock(kind="EXIF", offset=0, length=len(data), raw_bytes=bytes(data))
    parser = ExifParser()
    fields, findings, diags = parser.parse(block)
    # Should safely terminate without infinite loop or RecursionError
    assert isinstance(fields, list)


def test_bmff_zero_length_box_protection():
    # Build a BMFF container with a 0-length box that could cause infinite loop
    # ftyp box: length 16, type 'ftyp'
    # invalid box: length 0 (extends to EOF) or length < 8
    data = bytearray()
    data.extend(struct.pack(">I", 16))
    data.extend(b"ftypheic")
    data.extend(b"\x00\x00\x00\x00")
    # Next box with size 0
    data.extend(struct.pack(">I", 0))
    data.extend(b"meta")

    reader = BoundedReader(bytes(data))
    bmff_reader = BmffContainerReader()
    units, blocks, diags = bmff_reader.read(reader)
    assert len(units) >= 1
    # Must terminate without infinite loop
    assert units[0].name == "BOX_ftyp"
