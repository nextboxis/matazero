"""Tests for format detection and container readers."""

from imgint.core.sniff.detector import FormatDetector
from imgint.core.source.reader import BoundedReader
from imgint.core.container.jpeg import JpegContainerReader
from imgint.core.container.png import PngContainerReader


def test_format_detector_jpeg():
    data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xd9"
    reader = BoundedReader(data)
    detected = FormatDetector.detect(reader)
    assert detected is not None
    assert detected.format_name == "JPEG"
    assert detected.mime_type == "image/jpeg"


def test_format_detector_png():
    data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x00IEND\xaeB`\x82"
    reader = BoundedReader(data)
    detected = FormatDetector.detect(reader)
    assert detected is not None
    assert detected.format_name == "PNG"
    assert detected.mime_type == "image/png"


def test_jpeg_container_reader():
    dqt_payload = b"\x00" + bytes(range(64))
    dqt_len = len(dqt_payload) + 2
    dqt_segment = b"\xff\xdb" + dqt_len.to_bytes(2, "big") + dqt_payload
    app0_segment = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
    jpeg_bytes = b"\xff\xd8" + app0_segment + dqt_segment + b"\xff\xd9"

    reader = BoundedReader(jpeg_bytes)
    container_reader = JpegContainerReader()
    units, blocks, diagnostics = container_reader.read(reader)

    assert any(u.name == "SOI" for u in units)
    assert any("APP0" in u.name for u in units)
    assert any("DQT" in u.name for u in units)
    assert any(u.name == "EOI" for u in units)
    assert len(diagnostics) == 0


def test_png_container_reader():
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x00IEND\xaeB`\x82"
    reader = BoundedReader(png_bytes)
    container_reader = PngContainerReader()
    units, blocks, diagnostics = container_reader.read(reader)

    chunk_names = [u.name for u in units]
    assert "IHDR" in chunk_names
    assert "IEND" in chunk_names
