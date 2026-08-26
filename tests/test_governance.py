"""Tests for Governance layer per SRD GR-1.x - GR-3.x."""

import pytest
import json
from pathlib import Path
from imgint.core.governance.scope import AuthorizationScope, ScopeValidationError
from imgint.core.governance.audit import AuditLogger, verify_audit_chain
from imgint.core.governance.refusals import enforce_refusals, RefusalError
from imgint.core.evidence.store import EvidenceStore, EvidenceCustodyError


def test_scope_creation_and_validation(temp_dir, valid_scope):
    scope_file = temp_dir / "test_scope.json"
    valid_scope.save_to_file(scope_file, secret_key="test_secret_key_123")

    loaded = AuthorizationScope.load_from_file(scope_file, secret_key="test_secret_key_123")
    assert loaded.case_id == "CASE-TEST-001"
    assert not loaded.is_expired
    assert loaded.is_analyzer_permitted("fingerprint_engine", 2)


def test_expired_scope_refusal(temp_dir, expired_scope):
    scope_file = temp_dir / "expired.json"
    expired_scope.save_to_file(scope_file)

    # GR-1.3: System MUST refuse expired scope with no override
    with pytest.raises(ScopeValidationError) as exc:
        AuthorizationScope.load_from_file(scope_file)
    assert "expired" in str(exc.value).lower()


def test_scope_tamper_detection(temp_dir, valid_scope):
    scope_file = temp_dir / "tampered_scope.json"
    valid_scope.save_to_file(scope_file)

    # Tamper with scope content
    data = json.loads(scope_file.read_text(encoding="utf-8"))
    data["purpose"] = "Unauthorized Surveillance"
    scope_file.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ScopeValidationError) as exc:
        AuthorizationScope.load_from_file(scope_file)
    assert "integrity check failed" in str(exc.value).lower()


def test_refused_capabilities_enforcement():
    # GR-3.1: Face recognition refusal
    with pytest.raises(RefusalError) as exc:
        enforce_refusals({"biometric_face_recognition"})
    assert "refused" in str(exc.value).lower()

    # GR-3.2: Mass scraping refusal
    with pytest.raises(RefusalError):
        enforce_refusals({"bulk_platform_scraping"})

    # GR-3.6: Boolean verdict refusal
    with pytest.raises(RefusalError):
        enforce_refusals({"authenticity_verdict"})


def test_audit_log_hash_chain_and_tamper_verification(temp_dir):
    log_file = temp_dir / "audit.jsonl"
    logger = AuditLogger(log_file, scope_id="TEST-CASE")

    # Add several entries
    logger.log("action_1", "SUCCESS", target_hash="abc1")
    logger.log("action_2", "SUCCESS", target_hash="abc2")
    logger.log("action_3", "SUCCESS", target_hash="abc3")

    # Verify intact chain (GR-2.7)
    is_valid, broken_idx, msg = verify_audit_chain(log_file)
    assert is_valid is True
    assert broken_idx is None

    # Tamper with the second entry
    lines = log_file.read_text(encoding="utf-8").splitlines()
    second_entry = json.loads(lines[1])
    second_entry["action"] = "tampered_action"
    lines[1] = json.dumps(second_entry)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Verification must catch the broken link / tampered content
    is_valid, broken_idx, msg = verify_audit_chain(log_file)
    assert is_valid is False
    assert broken_idx == 1


def test_evidence_store_custody_and_hash_integrity(temp_dir, sample_jpeg):
    store_dir = temp_dir / "store"
    store = EvidenceStore(store_dir)

    ingested = store.ingest(sample_jpeg)
    assert ingested.sha256 != ""
    assert Path(ingested.stored_original_path).exists()
    assert Path(ingested.working_copy_path).exists()

    # Verification passes when originals are untouched
    store.verify_all_originals()

    # Tamper with original file to simulate custody breach
    orig_p = Path(ingested.stored_original_path)
    # Temporarily allow write to simulate tampering
    orig_p.chmod(0o777)
    orig_p.write_bytes(b"tampered_data")

    with pytest.raises(EvidenceCustodyError) as exc:
        store.verify_all_originals()
    assert "critical custody breach" in str(exc.value).lower()
