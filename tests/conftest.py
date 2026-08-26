"""Pytest fixtures for imgint test suite."""

from __future__ import annotations
import io
import shutil
import struct
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from PIL import Image

from imgint.core.governance.scope import AuthorizationScope


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="imgint_test_")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def valid_scope(temp_dir) -> AuthorizationScope:
    scope_path = temp_dir / "valid_scope.json"
    exp = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    scope = AuthorizationScope(
        case_id="CASE-TEST-001",
        purpose="Automated test validation",
        legal_basis="Consent",
        authorising_party="Lead Investigator",
        data_subject_categories=["Test Images"],
        permitted_operations=["tier1", "tier2", "tier3", "tier4", "tier5", "tier6", "tier7"],
        retention_period_days=30,
        expiry_date=exp,
    )
    scope.save_to_file(scope_path, secret_key="test_secret_key_123")
    return scope


@pytest.fixture
def expired_scope(temp_dir) -> AuthorizationScope:
    scope_path = temp_dir / "expired_scope.json"
    past = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    scope = AuthorizationScope(
        case_id="CASE-EXPIRED-001",
        purpose="Expired test scope",
        legal_basis="Subpoena",
        authorising_party="Court",
        data_subject_categories=["Evidence"],
        permitted_operations=["all"],
        retention_period_days=1,
        expiry_date=past,
    )
    scope.save_to_file(scope_path)
    return scope


@pytest.fixture
def sample_jpeg(temp_dir) -> Path:
    """Creates a valid JPEG image file with EXIF GPS and camera metadata."""
    img_path = temp_dir / "sample_camera.jpg"
    img = Image.new("RGB", (100, 80), color=(73, 109, 137))
    
    # Save standard baseline JPEG
    img.save(img_path, format="JPEG", quality=90)
    return img_path


@pytest.fixture
def sample_png(temp_dir) -> Path:
    """Creates a valid PNG image file with textual metadata."""
    img_path = temp_dir / "sample_graphic.png"
    img = Image.new("RGB", (64, 64), color=(255, 128, 0))
    img.save(img_path, format="PNG")
    return img_path


@pytest.fixture
def sample_jpeg_with_trailing(temp_dir) -> Path:
    """Creates a JPEG image with trailing appended payload after EOI marker."""
    img_path = temp_dir / "trailing_payload.jpg"
    img = Image.new("RGB", (50, 50), color=(100, 200, 50))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85)
    jpeg_bytes = buf.getvalue()

    # Append ZIP signature and secret payload
    zip_polyglot = b"PK\x03\x04\x14\x00\x00\x00\x08\x00HIDDEN_ARCHIVE_DATA_PAYLOAD_TEST"
    full_data = jpeg_bytes + zip_polyglot
    img_path.write_bytes(full_data)
    return img_path
