"""Security hardening and regression tests for ethical hacker vulnerability fixes (v2.3.0)."""

from __future__ import annotations
import io
import json
import os
import struct
import zipfile
import zlib
from pathlib import Path

import pytest
from PIL import Image

from imgint.core.governance.scope import AuthorizationScope, ScopeValidationError
from imgint.core.governance.refusals import RefusalError
from imgint.core.sandbox.process import SandboxRunner
from imgint.core.sandbox.worker import process_decode_tasks
from imgint.core.standard.png_native import PngNativeParser
from imgint.core.standard.xmp import XmpParser
from imgint.core.standard.office_props import OfficePropertiesParser
from imgint.core.container.office import OfficeContainerReader
from imgint.core.source.reader import BoundedReader
from imgint.core.model.record import AnalysisRecord, MetadataBlock, Field
from imgint.core.model.finding import Finding, Confidence
from imgint.core.report.html_renderer import HtmlReportRenderer
from imgint.core.geo.exporter import GeoExporter
from imgint.core.geo.locator import GeoLocator
from imgint.core.geo.sqlite_engine import NaturalEarthDB
from imgint.core.ai.ollama import OllamaClient
from imgint.core.skill.registry import SkillRegistry
from imgint.core.skill.manifest import SkillManifest
from imgint.core.evidence.store import EvidenceStore, EvidenceCustodyError
from imgint.core.crypto.ciphers import AesImageCipher, ArnoldCatMapCipher, MATA_CONTAINER_MAGIC
from imgint.core.stego.payload import LsbStego, LSB_MAGIC, TrailingPayload
from imgint.core.timeline.reconstructor import TimelineReconstructor
from imgint.core.cluster.engine import ClusterEngine


def test_scope_rejects_external_self_audit_escalation(tmp_path: Path):
    """Ensure external scope JSON cannot set is_self_audit=True to bypass expiry or permissions."""
    malicious_scope = {
        "case_id": "EVIL-001",
        "purpose": "Bypass expiry",
        "legal_basis": "None",
        "authorising_party": "Attacker",
        "data_subject_categories": ["All"],
        "permitted_operations": ["tier1"],
        "retention_period_days": 1,
        "expiry_date": "2020-01-01T00:00:00Z",
        "disabled_analyzers": [],
        "is_self_audit": True,
    }
    scope_file = tmp_path / "evil_scope.json"
    scope_file.write_text(json.dumps(malicious_scope), encoding="utf-8")

    with pytest.raises(ScopeValidationError, match="is_self_audit"):
        AuthorizationScope.load_from_file(scope_file)


def test_scope_refuses_prohibited_operations_even_in_self_audit():
    """Prohibited operations (e.g. facial_recognition) must be refused even when is_self_audit=True."""
    with pytest.raises(RefusalError):
        AuthorizationScope(
            case_id="SELF_AUDIT",
            purpose="Test",
            legal_basis="Consent",
            authorising_party="User",
            data_subject_categories=["User"],
            permitted_operations=["tier1", "facial_recognition"],
            retention_period_days=0,
            expiry_date="2099-01-01T00:00:00Z",
            is_self_audit=True,
        )


def test_sandbox_env_scrubs_secrets_and_proxies(monkeypatch):
    """Ensure SandboxRunner._build_sanitized_env strips tokens, keys, passwords, and proxy vars."""
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "super-secret-aws-key")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret123")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret")
    monkeypatch.setenv("HTTP_PROXY", "http://evil-proxy:8080")
    monkeypatch.setenv("DB_PASSWORD", "hunter2")

    env = SandboxRunner._build_sanitized_env("J:\\Projects\\06_Mata")
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert "OPENAI_API_KEY" not in env
    assert "HTTP_PROXY" not in env
    assert "DB_PASSWORD" not in env
    assert env.get("PYTHONNOUSERSITE") == "1"
    assert env.get("NO_PROXY") == "*"


def test_worker_crop_blocks_path_traversal_and_bad_extensions(tmp_path: Path):
    """Ensure sandbox worker blocks '..' traversal and non-image extensions in crop_out_path."""
    img_path = tmp_path / "src.png"
    Image.new("RGB", (32, 32), color="red").save(img_path)

    res_traversal = process_decode_tasks({
        "file_path": str(img_path),
        "tasks": ["crop"],
        "x": 0, "y": 0, "width": 10, "height": 10,
        "crop_out_path": str(tmp_path / ".." / "escaped.png"),
    })
    assert "error" in res_traversal["tasks"]["crop"]

    res_ext = process_decode_tasks({
        "file_path": str(img_path),
        "tasks": ["crop"],
        "x": 0, "y": 0, "width": 10, "height": 10,
        "crop_out_path": str(tmp_path / "malicious.py"),
    })
    assert "error" in res_ext["tasks"]["crop"]


def test_png_ztxt_zlib_bomb_blocked():
    """Ensure PngNativeParser blocks oversized zlib payloads (> 1 MB)."""
    parser = PngNativeParser()
    # Compress 2 MB of zeros (compresses to ~2 KB)
    compressed_bomb = zlib.compress(b"A" * (2 * 1024 * 1024))
    raw_ztxt = b"Comment\x00\x00" + compressed_bomb
    block = MetadataBlock(kind="PNG_TEXT", offset=0, length=len(raw_ztxt), raw_bytes=raw_ztxt, source_unit="PNG_zTXt")

    fields, findings, diags = parser.parse(block)
    assert len(fields) == 0
    assert any("zlib bomb" in d.message or "exceeds maximum safety limit" in d.message for d in diags)


def test_xmp_and_office_reject_xxe_doctype():
    """Ensure XmpParser and OfficePropertiesParser reject <!DOCTYPE and <!ENTITY declarations."""
    xxe_payload = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        b'<rdf:Description><dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">&lol2;</dc:title></rdf:Description>'
        b'</rdf:RDF></x:xmpmeta>'
    )
    xmp_block = MetadataBlock(kind="XMP", offset=0, length=len(xxe_payload), raw_bytes=xxe_payload, source_unit="APP1_XMP")
    fields, findings, diags = XmpParser().parse(xmp_block)
    assert len(fields) == 0
    assert any("DTD or ENTITY" in d.message for d in diags)

    office_block = MetadataBlock(kind="OFFICE_CORE_PROPERTIES", offset=0, length=len(xxe_payload), raw_bytes=xxe_payload, source_unit="docProps/core.xml")
    o_fields, o_findings, _ = OfficePropertiesParser().parse(office_block)
    assert len(o_fields) == 0


def test_office_container_blocks_zip_bomb_and_zip_slip():
    """Ensure OfficeContainerReader rejects high-ratio ZIP bombs inside ppt/media/."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # 5 MB of zeros compresses to ~5 KB (~1000x ratio > 100x limit)
        zf.writestr("ppt/media/bomb.jpg", b"\x00" * (5 * 1024 * 1024))

    reader = BoundedReader(buf.getvalue())
    units, blocks, diags = OfficeContainerReader().read(reader)
    assert any("bomb" in d.message.lower() or "ratio" in d.message.lower() for d in diags)


def test_html_and_leaflet_xss_sanitization():
    """Ensure HtmlReportRenderer and GeoExporter escape XSS payloads in filenames, places, and scopes."""
    xss_payload = "<script>alert('XSS')</script><img src=x onerror=alert(1)>"
    rec = AnalysisRecord(
        file_path=f"/tmp/{xss_payload}.jpg",
        file_size=1024,
        mime_type=f"image/jpeg\">{xss_payload}",
        sha256="a" * 64,
        tool_version="2.3.0",
        corpus_version="2026.09",
        scope_id=xss_payload,
    )
    rec.add_finding(Finding(
        name="offline_reverse_geocode",
        value={"closest_city": xss_payload, "country": xss_payload},
        tier=5,
        extractor="test",
        confidence=Confidence.DERIVED,
        caveat="Test reverse geocode caveat",
    ))
    rec.add_finding(Finding(
        name="dominant_color_palette",
        value={"dominant_hex": "red; background:url(javascript:alert(1))"},
        tier=7,
        extractor="test",
        confidence=Confidence.OBSERVED,
        caveat=None,
    ))

    html_out = HtmlReportRenderer.render_html(rec)
    assert "<script>alert('XSS')</script>" not in html_out
    assert 'style="background-color: #1B4255;"' in html_out
    assert 'style="background-color: red;' not in html_out

    leaflet_out = GeoExporter.to_leaflet_html(
        [{"latitude": 13.0827, "longitude": 80.2707, "file_name": xss_payload, "closest_city": xss_payload}],
        title=xss_payload,
    )
    assert f"<title>{xss_payload}</title>" not in leaflet_out
    assert "</script><img" not in leaflet_out

    kml_out = GeoExporter.to_kml(
        [{"latitude": 13.0827, "longitude": 80.2707, "file_name": "test]]><script>alert(1)</script>"}],
        doc_name=xss_payload,
    )
    assert "]]><script>" not in kml_out


def test_ollama_client_blocks_ssrf_and_file_scheme():
    """Ensure OllamaClient rejects file:// scheme and non-loopback remote hosts by default."""
    with pytest.raises(ValueError, match="scheme"):
        OllamaClient(host="file:///etc/passwd")

    with pytest.raises(ValueError, match="Remote Ollama host"):
        OllamaClient(host="http://169.254.169.254:80")

    local_client = OllamaClient(host="http://127.0.0.1:11434")
    assert local_client.host == "http://127.0.0.1:11434"


def test_geo_resolve_ip_online_blocks_private_and_injected_ips():
    """Ensure resolve_ip_online rejects private/loopback and URL-injected IP strings without network calls."""
    assert GeoLocator.resolve_ip_online("127.0.0.1") is None
    assert GeoLocator.resolve_ip_online("192.168.1.1") is None
    assert GeoLocator.resolve_ip_online("1.1.1.1/../../evil?x=1") is None


def test_natural_earth_sqlite_path_resolved():
    """Verify NaturalEarthDB resolves the local sqlite database in J:\\Projects\\06_Mata."""
    db = NaturalEarthDB.get_instance()
    if db.db_path and Path(db.db_path).exists():
        assert db.is_available
        res = db.reverse_geocode(13.0827, 80.2707)
        assert res is not None
        assert res.country_code == "IN"


def test_skill_registry_blocks_path_traversal(tmp_path: Path):
    """Ensure SkillRegistry._load_skill_from_directory rejects '../' entry_point traversal."""
    reg = SkillRegistry()
    manifest = SkillManifest(
        id="evil_skill",
        name="Evil",
        version="1.0.0",
        description="Path traversal test",
        author="Attacker",
        target_tier=6,
        entry_point="../outside.py:EvilSkill",
    )
    with pytest.raises(ValueError, match="path traversal"):
        reg._load_skill_from_directory(tmp_path, manifest)


def test_evidence_store_detects_tampered_original_on_reingest(tmp_path: Path):
    """Ensure EvidenceStore.ingest verifies existing original file hash on re-ingestion."""
    store = EvidenceStore(tmp_path / "vault")
    sample = tmp_path / "evidence.jpg"
    sample.write_bytes(b"\xFF\xD8\xFF\xD9")

    ev = store.ingest(sample)
    orig_stored = Path(ev.stored_original_path)
    orig_stored.chmod(0o666)
    orig_stored.write_bytes(b"TAMPERED_BYTES")

    with pytest.raises(EvidenceCustodyError, match="CRITICAL CUSTODY BREACH"):
        store.ingest(sample)


def test_crypto_and_stego_bounds_validation(tmp_path: Path):
    """Ensure truncated containers, invalid CBC padding, and oversized LSB headers raise clean ValueErrors."""
    trunc_file = tmp_path / "trunc.enc"
    trunc_file.write_bytes(MATA_CONTAINER_MAGIC + b"short")
    with pytest.raises(ValueError, match="Truncated"):
        AesImageCipher.decrypt_file(trunc_file, tmp_path / "out.bin", "pass")

    img = Image.new("RGB", (16, 16), color="green")
    with pytest.raises(ValueError, match="iterations"):
        ArnoldCatMapCipher.process(img, iterations=5000)

    # Craft image with LSB header claiming 100 MB payload inside 16x16 image
    import numpy as np
    bad_packet = LSB_MAGIC + b"\x00" + struct.pack(">I", 100_000_000)
    packet_bits = np.unpackbits(np.frombuffer(bad_packet, dtype=np.uint8))
    arr = np.array(img).reshape(-1)
    arr[: len(packet_bits)] = (arr[: len(packet_bits)] & 0xFE) | packet_bits
    crafted = Image.fromarray(arr.reshape((16, 16, 3)), mode="RGB")

    with pytest.raises(ValueError, match="exceeds carrier capacity"):
        LsbStego.extract(crafted)


def test_timeline_and_cluster_sub_ifd_field_resolution(tmp_path: Path):
    """Ensure TimelineReconstructor and ClusterEngine resolve ExifSubIFD: and GPSInfo: prefixed fields."""
    img_path = tmp_path / "IMG_001.jpg"
    Image.new("RGB", (16, 16), color="white").save(img_path, format="JPEG")

    rec = AnalysisRecord(
        file_path=str(img_path),
        file_size=img_path.stat().st_size,
        mime_type="image/jpeg",
        sha256="b" * 64,
        tool_version="2.3.0",
        corpus_version="2026.09",
    )
    rec.fields = [
        Field(standard="EXIF", name="Make", value="Canon", raw_value="Canon", value_type="ASCII"),
        Field(standard="EXIF", name="Model", value="EOS R5", raw_value="EOS R5", value_type="ASCII"),
        Field(standard="EXIF", name="ExifSubIFD:DateTimeOriginal", value="2026:09:01 12:00:00", raw_value=0, value_type="ASCII"),
        Field(standard="EXIF", name="ExifSubIFD:BodySerialNumber", value="SN998877", raw_value=0, value_type="ASCII"),
        Field(standard="EXIF", name="GPSInfo:GPSDateStamp", value="2026:09:01", raw_value=0, value_type="ASCII"),
        Field(standard="EXIF", name="GPSInfo:GPSTimeStamp", value=[[12, 1], [0, 1], [0, 1]], raw_value=0, value_type="RATIONAL[]"),
    ]

    ev = TimelineReconstructor._extract_event_from_record(img_path, rec)
    assert ev.timestamp_source == "EXIF_DateTimeOriginal"
    assert ev.gps_satellite_time is not None
    assert ev.camera_clock_drift_seconds == 0.0

    item = ClusterEngine._extract_clustered_item(img_path, rec)
    assert item.serial_number == "SN998877"
    assert item.camera_make == "Canon"
