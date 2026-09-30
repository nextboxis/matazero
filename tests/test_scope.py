"""Tests for AuthorizationScope validation, HMAC signing, and expiry."""

from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

from imgint.core.governance.scope import AuthorizationScope, ScopeValidationError


def test_scope_creation_and_hash():
    exp = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    scope = AuthorizationScope(
        case_id="CASE-2026-TEST",
        purpose="Investigate digital evidence integrity",
        legal_basis="Consent",
        authorising_party="Lead Investigator",
        data_subject_categories=["Evidence Images"],
        permitted_operations=["tier1", "tier2", "tier3"],
        retention_period_days=30,
        expiry_date=exp,
    )
    assert not scope.is_expired
    h = scope.compute_canonical_hash()
    assert len(h) == 64
    assert scope.is_analyzer_permitted("exif_parser", 1) is True


def test_scope_hmac_signing_and_verification(tmp_path: Path):
    scope_path = tmp_path / "test_scope.json"
    secret = "TopSecretForensicKey123"
    exp = (datetime.now(timezone.utc) + timedelta(days=14)).isoformat()

    scope = AuthorizationScope(
        case_id="CASE-SIGNED",
        purpose="Integrity verification",
        legal_basis="Subpoena",
        authorising_party="Court Order",
        data_subject_categories=["Files"],
        permitted_operations=["tier1", "tier2"],
        retention_period_days=14,
        expiry_date=exp,
    )
    scope.save_to_file(scope_path, secret_key=secret)

    loaded = AuthorizationScope.load_from_file(scope_path, secret_key=secret)
    assert loaded.case_id == "CASE-SIGNED"
    assert loaded.signature is not None

    with pytest.raises(ScopeValidationError):
        AuthorizationScope.load_from_file(scope_path, secret_key="WrongKey456")


def test_scope_expired_rejection(tmp_path: Path):
    scope_path = tmp_path / "expired_scope.json"
    past_exp = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

    scope = AuthorizationScope(
        case_id="CASE-EXPIRED",
        purpose="Testing expiration",
        legal_basis="Audit",
        authorising_party="Admin",
        data_subject_categories=["Files"],
        permitted_operations=["tier1"],
        retention_period_days=1,
        expiry_date=past_exp,
    )
    scope.save_to_file(scope_path)

    with pytest.raises(ScopeValidationError, match="expired"):
        AuthorizationScope.load_from_file(scope_path)
