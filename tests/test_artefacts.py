"""Tests for Embedded Artefacts per SRD FR-4.x."""

import pytest
from imgint.core.source.reader import BoundedReader
from imgint.core.container.jpeg import JpegContainerReader
from imgint.core.artefact.trailing import TrailingDataExtractor


def test_trailing_data_detection_and_entropy(sample_jpeg_with_trailing):
    reader = BoundedReader(sample_jpeg_with_trailing)
    jpeg_reader = JpegContainerReader()
    units, blocks, diags = jpeg_reader.read(reader)

    trailing_unit = next((u for u in units if u.name == "TRAILING_DATA"), None)
    assert trailing_unit is not None
    assert trailing_unit.length > 0

    info = TrailingDataExtractor.analyze(trailing_unit, reader.get_all_bytes())
    assert info.shannon_entropy > 0
    assert "ZIP" in info.detected_payload_type or "Polyglot" in info.detected_payload_type
