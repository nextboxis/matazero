"""Tests for SQLite and STIX 2.1 Exporters."""

import pytest
import sqlite3
from pathlib import Path
from PIL import Image
from imgint.core.pipeline import AnalysisPipeline
from imgint.core.governance.scope import AuthorizationScope
from imgint.core.export import SqliteExporter, StixExporter


@pytest.fixture
def analyzed_records(tmp_path):
    p = tmp_path / "sample.jpg"
    Image.new("RGB", (64, 64), color="magenta").save(p, "JPEG", quality=90)

    scope = AuthorizationScope.create_self_audit_scope()
    pipeline = AnalysisPipeline(scope=scope, selected_tiers={1, 2, 3, 4, 5, 6, 7})
    rec = pipeline.analyze_file(p)
    return [rec]


def test_sqlite_export(analyzed_records, tmp_path):
    db_path = tmp_path / "test_export.db"
    out_path = SqliteExporter.export(analyzed_records, db_path)
    assert Path(out_path).exists()

    conn = sqlite3.connect(out_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM images")
    count = cur.fetchone()[0]
    assert count == 1

    cur.execute("SELECT sha256, mime_type FROM images")
    row = cur.fetchone()
    assert row[0] == analyzed_records[0].sha256
    assert row[1] == "image/jpeg"
    conn.close()


def test_stix_export(analyzed_records):
    bundle = StixExporter.export(analyzed_records)
    assert bundle["type"] == "bundle"
    assert "objects" in bundle
    assert len(bundle["objects"]) >= 1
    file_sco = next((o for o in bundle["objects"] if o["type"] == "file"), None)
    assert file_sco is not None
    assert file_sco["hashes"]["SHA-256"] == analyzed_records[0].sha256
