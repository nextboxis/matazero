"""Tests for tamper-evident hash-chained audit logging and concurrency."""

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest

from imgint.core.governance.audit import AuditLogger, AuditEntry, verify_audit_chain


def test_audit_entry_hash_determinism():
    entry = AuditEntry(
        entry_index=0,
        timestamp_utc="2026-09-11T00:00:00Z",
        operator="analyst",
        scope_id="SCOPE-TEST-001",
        action="file_analyzed",
        outcome="SUCCESS",
        previous_hash="0" * 64,
        target_hash="a" * 64,
        details={"file_name": "sample.jpg"},
    )
    h1 = entry.compute_hash()
    h2 = entry.compute_hash()
    assert len(h1) == 64
    assert h1 == h2


def test_audit_logger_sequential_chain(tmp_path: Path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_file, scope_id="CASE-001")

    e1 = logger.log("ingest", outcome="SUCCESS", target_hash="11" * 32)
    assert e1.entry_index == 0
    assert e1.previous_hash == AuditLogger.GENESIS_HASH

    e2 = logger.log("analyze", outcome="SUCCESS", target_hash="22" * 32)
    assert e2.entry_index == 1
    assert e2.previous_hash == e1.entry_hash

    is_valid, broken_idx, msg = verify_audit_chain(log_file)
    assert is_valid is True
    assert broken_idx is None


def test_audit_logger_tamper_detection(tmp_path: Path):
    log_file = tmp_path / "audit_tampered.jsonl"
    logger = AuditLogger(log_file, scope_id="CASE-002")

    logger.log("step_1", outcome="SUCCESS")
    logger.log("step_2", outcome="SUCCESS")
    logger.log("step_3", outcome="SUCCESS")

    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    tampered_entry = json.loads(lines[1])
    tampered_entry["action"] = "tampered_unauthorized_action"
    lines[1] = json.dumps(tampered_entry)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    is_valid, broken_idx, msg = verify_audit_chain(log_file)
    assert is_valid is False
    assert broken_idx == 1


def test_audit_logger_concurrent_thread_safety(tmp_path: Path):
    log_file = tmp_path / "audit_concurrent.jsonl"
    logger = AuditLogger(log_file, scope_id="CASE-CONCURRENT")

    num_threads = 8
    entries_per_thread = 10
    total_entries = num_threads * entries_per_thread

    def _worker(thread_id: int):
        for i in range(entries_per_thread):
            logger.log(
                action=f"worker_{thread_id}_step_{i}",
                outcome="SUCCESS",
                details={"thread_id": thread_id, "iteration": i},
            )

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(_worker, tid) for tid in range(num_threads)]
        for f in futures:
            f.result()

    lines = [l for l in log_file.read_text(encoding="utf-8").strip().splitlines() if l]
    assert len(lines) == total_entries

    is_valid, broken_idx, msg = verify_audit_chain(log_file)
    assert is_valid is True, f"Audit chain broken at index {broken_idx}: {msg}"
