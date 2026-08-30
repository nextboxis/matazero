"""Tests for Evidence Repository Pattern (Filesystem and SQLite)."""

import pytest
from pathlib import Path
from PIL import Image
from imgint.core.pipeline import AnalysisPipeline
from imgint.core.governance.scope import AuthorizationScope
from imgint.core.repository import FilesystemEvidenceRepository, SqliteEvidenceRepository


@pytest.fixture
def sample_record(tmp_path):
    img_path = tmp_path / "repo_test.jpg"
    Image.new("RGB", (64, 64), color="blue").save(img_path, "JPEG", quality=90)
    pipeline = AnalysisPipeline(scope=AuthorizationScope.create_self_audit_scope(), selected_tiers={1, 2, 4, 6})
    return pipeline.analyze_file(img_path)


def test_filesystem_repository(sample_record, tmp_path):
    repo = FilesystemEvidenceRepository(root_dir=tmp_path / "evidence_fs")
    assert repo.count() == 0

    repo.save(sample_record)
    assert repo.count() == 1

    fetched = repo.get_by_sha256(sample_record.sha256)
    assert fetched is not None
    assert fetched.sha256 == sample_record.sha256

    all_items = repo.list_all()
    assert len(all_items) == 1

    assert repo.delete(sample_record.sha256) is True
    assert repo.count() == 0


def test_sqlite_repository(sample_record, tmp_path):
    repo = SqliteEvidenceRepository(db_path=tmp_path / "repo_test.db")
    assert repo.count() == 0

    repo.save(sample_record)
    assert repo.count() == 1

    fetched = repo.get_by_sha256(sample_record.sha256)
    assert fetched is not None
    assert fetched.sha256 == sample_record.sha256

    all_items = repo.list_all()
    assert len(all_items) == 1

    assert repo.delete(sample_record.sha256) is True
    assert repo.count() == 0
