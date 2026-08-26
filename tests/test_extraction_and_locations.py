"""Tests for value locations, -x -y extraction, and ArtefactExtractor."""

import io
import struct
import tempfile
from pathlib import Path
from PIL import Image

from imgint.core.model.record import Field, MetadataBlock
from imgint.core.standard.exif import ExifParser
from imgint.core.standard.png_native import PngNativeParser
from imgint.core.standard.iptc import IptcParser
from imgint.core.standard.icc import IccParser
from imgint.core.analyzer.tier5_geotime import GeoTimeAnalyzer
from imgint.core.analyzer.base import AnalysisContext
from imgint.core.source.reader import BoundedReader
from imgint.core.artefact.extractor import ArtefactExtractor
from imgint.core.pipeline import AnalysisPipeline
from imgint.core.governance.scope import AuthorizationScope


from fractions import Fraction

def create_sample_jpeg_with_exif_and_trailing() -> Path:
    """Create a temporary JPEG with EXIF metadata, GPS coordinates, and trailing ZIP."""
    img = Image.new("RGB", (100, 100), color=(120, 150, 200))
    # Exif data
    exif = img.getexif()
    exif[0x010F] = "CameraMaker"
    exif[0x0110] = "CameraModel"
    exif[0x0132] = "2026:08:26 12:00:00"

    # Add GPS IFD (0x8825)
    gps_ifd = exif.get_ifd(0x8825)
    gps_ifd[0x0001] = "N"
    gps_ifd[0x0002] = (Fraction(37, 1), Fraction(46, 1), Fraction(2974, 100))
    gps_ifd[0x0003] = "W"
    gps_ifd[0x0004] = (Fraction(122, 1), Fraction(25, 1), Fraction(984, 100))
    gps_ifd[0x0006] = Fraction(50, 1)
    gps_ifd[0x001D] = "2026:08:26"

    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif)
    jpeg_bytes = buf.getvalue()

    # Append a fake trailing ZIP payload (PK\x03\x04...)
    fake_zip = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"TEST_PAYLOAD_CONTENT"
    full_data = jpeg_bytes + fake_zip

    tmp = tempfile.NamedTemporaryFile(suffix=".jpg", delete=False)
    tmp.write(full_data)
    tmp.close()
    return Path(tmp.name)


def test_field_value_locations_model():
    f = Field(
        standard="EXIF",
        name="Make",
        value="CameraMaker",
        raw_value=123,
        value_type="ASCII",
        tag_id="0x010F",
        offset=0x100,
        value_offset=0x120,
        length=11,
    )
    d = f.to_dict()
    assert d["offset"] == 0x100
    assert d["value_offset"] == 0x120
    assert d["length"] == 11
    assert d["name"] == "Make"


def test_exif_parser_value_locations():
    p = create_sample_jpeg_with_exif_and_trailing()
    try:
        pipeline = AnalysisPipeline(scope=AuthorizationScope.create_self_audit_scope())
        rec = pipeline.analyze_file(p)

        # Check fields have offsets and value_offsets
        assert len(rec.fields) > 0
        fields_with_val_offset = [f for f in rec.fields if f.value_offset is not None]
        assert len(fields_with_val_offset) > 0

        # Check GPS coordinates finding has X, Y and value locations
        gps_finding = next((f for f in rec.findings if f.name == "gps_coordinates_claimed"), None)
        assert gps_finding is not None
        val = gps_finding.value
        assert "x" in val
        assert "y" in val
        assert "x_value_location" in val
        assert "y_value_location" in val
        assert val["y"] > 37.0  # Latitude (Y)
        assert val["x"] < -122.0  # Longitude (X)

        # Check trailing data detected
        trailing_finding = next((f for f in rec.findings if f.name == "trailing_data_detected"), None)
        assert trailing_finding is not None
        assert "ZIP" in trailing_finding.value["detected_payload_type"]

    finally:
        if p.exists():
            p.unlink()


def test_artefact_extractor_and_crop():
    p = create_sample_jpeg_with_exif_and_trailing()
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            extracted = ArtefactExtractor.extract_all(
                file_path=p,
                out_dir=tmp_dir,
                include_metadata=True,
                include_thumbnail=True,
                include_preview=True,
                include_payload=True,
                crop_coords={"x": 10, "y": 10, "width": 50, "height": 50},
            )

            assert len(extracted) > 0
            types = {it.item_type for it in extracted}
            # Payload and metadata should be extracted
            assert "payload" in types or "metadata_block" in types
            assert "crop" in types

            crop_item = next(it for it in extracted if it.item_type == "crop")
            assert Path(crop_item.output_path).exists()
            assert crop_item.details["x"] == 10
            assert crop_item.details["y"] == 10

    finally:
        if p.exists():
            p.unlink()


if __name__ == "__main__":
    print("Running test_field_value_locations_model...")
    test_field_value_locations_model()
    print("Running test_exif_parser_value_locations...")
    test_exif_parser_value_locations()
    print("Running test_artefact_extractor_and_crop...")
    test_artefact_extractor_and_crop()
    print("ALL TESTS PASSED SUCCESSFULLY!")
