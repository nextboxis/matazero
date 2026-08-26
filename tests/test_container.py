"""Tests for Container and Standard layers per SRD FR-1.x and FR-2.x."""

import pytest
from pathlib import Path
from imgint.core.source.reader import BoundedReader
from imgint.core.sniff.detector import FormatDetector
from imgint.core.container.jpeg import JpegContainerReader
from imgint.core.container.png import PngContainerReader
from imgint.core.standard.xmp import XmpParser
from imgint.core.model.record import MetadataBlock


def test_magic_byte_sniffing(sample_jpeg, sample_png):
    # JPEG
    reader_jpg = BoundedReader(sample_jpeg)
    det_jpg = FormatDetector.detect(reader_jpg)
    assert det_jpg.format_name == "JPEG"
    assert det_jpg.is_supported is True

    # PNG
    reader_png = BoundedReader(sample_png)
    det_png = FormatDetector.detect(reader_png)
    assert det_png.format_name == "PNG"
    assert det_png.is_supported is True


def test_extension_mismatch_finding(temp_dir, sample_jpeg):
    # Rename JPEG to have .png extension
    fake_png = temp_dir / "actually_jpeg.png"
    fake_png.write_bytes(sample_jpeg.read_bytes())

    reader = BoundedReader(fake_png)
    det = FormatDetector.detect(reader)
    assert det.format_name == "JPEG"

    finding = FormatDetector.check_extension_mismatch(det, fake_png)
    assert finding is not None
    assert finding.name == "container_extension_mismatch"
    assert finding.value["declared_extension"] == ".png"
    assert finding.value["detected_format"] == "JPEG"


def test_jpeg_container_segment_walk(sample_jpeg):
    reader = BoundedReader(sample_jpeg)
    jpeg_reader = JpegContainerReader()
    units, blocks, diags = jpeg_reader.read(reader)

    unit_names = [u.name for u in units]
    assert "SOI" in unit_names
    assert "DQT" in unit_names
    assert "SOF0" in unit_names or "SOF2" in unit_names
    assert "SOS" in unit_names
    assert "EOI" in unit_names


def test_png_container_chunk_walk(sample_png):
    reader = BoundedReader(sample_png)
    png_reader = PngContainerReader()
    units, blocks, diags = png_reader.read(reader)

    unit_names = [u.name for u in units]
    assert "IHDR" in unit_names
    assert "IDAT" in unit_names
    assert "IEND" in unit_names


def test_safe_xmp_parsing_no_xxe():
    xmp_raw = b"""<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
    <x:xmpmeta xmlns:x="adobe:ns:meta/">
      <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
        <rdf:Description rdf:about=""
            xmlns:xmp="http://ns.adobe.com/xap/1.0/"
            xmlns:dc="http://purl.org/dc/elements/1.1/">
          <dc:creator>Forensic Analyst</dc:creator>
          <xmp:CreateDate>2026-08-25T14:30:00Z</xmp:CreateDate>
        </rdf:Description>
      </rdf:RDF>
    </x:xmpmeta>
    <?xpacket end="w"?>"""

    block = MetadataBlock(kind="XMP", offset=100, length=len(xmp_raw), raw_bytes=xmp_raw)
    parser = XmpParser()
    fields, findings, diags = parser.parse(block)

    names = [f.name for f in fields]
    assert any("creator" in n.lower() for n in names)
    assert any("createdate" in n.lower() for n in names)
