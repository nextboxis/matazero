"""Tests for Extended Containers (GIF, WebP/RIFF, BMP, TIFF, Office)."""

import pytest
import zipfile
from pathlib import Path
from PIL import Image
from imgint.core.pipeline import AnalysisPipeline
from imgint.core.governance.scope import AuthorizationScope


@pytest.fixture
def pipeline():
    scope = AuthorizationScope.create_self_audit_scope()
    return AnalysisPipeline(scope=scope, selected_tiers={1, 2, 4, 6})


def test_gif_container_parsing(pipeline, tmp_path):
    p = tmp_path / "sample.gif"
    img = Image.new("P", (50, 50), color=3)
    img.save(p, "GIF")

    rec = pipeline.analyze_file(p)
    assert rec.mime_type == "image/gif"
    assert len(rec.structural_units) > 0


def test_bmp_container_parsing(pipeline, tmp_path):
    p = tmp_path / "sample.bmp"
    img = Image.new("RGB", (32, 32), color="orange")
    img.save(p, "BMP")

    rec = pipeline.analyze_file(p)
    assert rec.mime_type == "image/bmp"
    assert len(rec.structural_units) > 0


def test_tiff_container_parsing(pipeline, tmp_path):
    p = tmp_path / "sample.tiff"
    img = Image.new("RGB", (32, 32), color="blue")
    img.save(p, "TIFF")

    rec = pipeline.analyze_file(p)
    assert rec.mime_type == "image/tiff"
    assert len(rec.structural_units) > 0


def test_webp_container_parsing(pipeline, tmp_path):
    p = tmp_path / "sample.webp"
    img = Image.new("RGB", (32, 32), color="teal")
    img.save(p, "WEBP")

    rec = pipeline.analyze_file(p)
    assert rec.mime_type == "image/webp"
    assert len(rec.structural_units) > 0


def test_office_docx_parsing(pipeline, tmp_path):
    p = tmp_path / "document.docx"
    # Create minimal valid zip structure for docx
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr("docProps/core.xml", '<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Forensic Analyst</dc:creator></cp:coreProperties>')
        zf.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Case notes</w:t></w:r></w:p></w:body></w:document>')

    rec = pipeline.analyze_file(p)
    assert "openxmlformats" in rec.mime_type or "zip" in rec.mime_type or "word" in rec.mime_type
    assert len(rec.fields) > 0
    author_f = next((f for f in rec.fields if "Author" in f.name or "creator" in f.name.lower()), None)
    assert author_f is not None
    assert author_f.value == "Forensic Analyst"
