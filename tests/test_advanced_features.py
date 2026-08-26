"""Tests for advanced features: HTML dossier, payload carving, user corpus learning, and C2PA."""

import hashlib
import json
import os
import tempfile
from pathlib import Path
from imgint.core.artefact.carver import PayloadCarver
from imgint.core.container.jpeg import JpegContainerReader
from imgint.core.fingerprint.corpus import ReferenceCorpus, CorpusEntry
from imgint.core.governance.scope import AuthorizationScope
from imgint.core.model.record import AnalysisRecord, StructuralUnit, MetadataBlock
from imgint.core.pipeline import AnalysisPipeline
from imgint.core.report.html_renderer import HtmlReportRenderer
from imgint.core.source.reader import BoundedReader
from imgint.core.standard.c2pa import C2paParser


def test_html_report_generation(tmp_path: Path):
    """Test interactive standalone HTML evidence dossier rendering."""
    img_path = Path("samples/evidence_sample.jpg") if Path("samples/evidence_sample.jpg").exists() else Path("plan.jpeg")
    if not img_path.exists():
        return

    scope = AuthorizationScope.create_self_audit_scope()
    pipeline = AnalysisPipeline(scope=scope, selected_tiers={1, 2, 4, 7})
    record = pipeline.analyze_file(str(img_path))

    html = HtmlReportRenderer.render_html(record)
    assert "<!DOCTYPE html>" in html
    assert "matazero Dossier" in html
    assert "Tier 2" in html
    assert "Solar Chronolocation" in html

    out_file = tmp_path / "dossier.html"
    out_file.write_text(html, encoding="utf-8")
    assert out_file.exists()
    assert out_file.stat().st_size > 1000


def test_payload_carver_trailing_zip(tmp_path: Path):
    """Test automatic trailing payload detection and extraction."""
    # Create fake JPEG container with trailing ZIP
    fake_jpeg = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00\xAA\xFF\xD9"
    fake_zip = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"TEST_PAYLOAD_CONTENT"
    combined = fake_jpeg + fake_zip

    carrier_file = tmp_path / "carrier.jpg"
    carrier_file.write_bytes(combined)

    reader = BoundedReader(carrier_file)
    jpeg_reader = JpegContainerReader()
    units, blocks, diags = jpeg_reader.read(reader)

    carve_dir = tmp_path / "carved"
    carved = PayloadCarver.carve_trailing_payload(reader, units, carve_dir)

    assert carved is not None
    assert carved.payload_type == "ZIP Archive"
    assert carved.size == len(fake_zip)
    assert Path(carved.output_path).exists()
    assert Path(carved.output_path).read_bytes() == fake_zip


def test_corpus_user_learning(tmp_path: Path):
    """Test registering a custom device profile to user corpus."""
    entry = CorpusEntry(
        entry_id="test_custom_drone_cam",
        device_model="Custom Hexacopter 4K Camera",
        encoder_software="FPGA ISP v1.0",
        processing_chain="On-board hardware pipeline",
        subsampling="4:2:2",
        dqt_luminance_sample=[10, 10, 10, 10, 12, 14, 16, 18],
        segment_prefix=["SOI", "APP0", "DQT", "SOF0"],
        confidence="indicative",
    )

    ref_corpus = ReferenceCorpus()
    ref_corpus.add_user_entry(entry)

    # Re-instantiate to verify disk reload
    reloaded_corpus = ReferenceCorpus()
    found = [e for e in reloaded_corpus.entries if e.entry_id == "test_custom_drone_cam"]
    assert len(found) == 1
    assert found[0].device_model == "Custom Hexacopter 4K Camera"


def test_c2pa_manifest_parsing():
    """Test C2PA authenticity parser with declared actions."""
    fake_c2pa_data = b"jumb\x00\x00\x00\x20c2pa claim_generator: \"Adobe Firefly 2026\" c2pa.created c2pa.edited"
    block = MetadataBlock(
        kind="C2PA",
        offset=100,
        length=len(fake_c2pa_data),
        raw_bytes=fake_c2pa_data,
        source_unit="APP11",
    )

    parser = C2paParser()
    assert parser.handles("C2PA")

    fields, findings, diags = parser.parse(block)
    assert len(findings) == 1
    val = findings[0].value
    assert val["present"] is True
    assert "Adobe Firefly 2026" in val["claim_generator"]
    assert "c2pa.created" in val["actions_history"]
    assert "c2pa.edited" in val["actions_history"]
