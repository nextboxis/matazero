"""Append-only hash-chained audit logging per SRD GR-2.4 - GR-2.7."""

from __future__ import annotations
import getpass
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class AuditEntry:
    entry_index: int
    timestamp_utc: str
    operator: str
    scope_id: str
    action: str
    outcome: str
    previous_hash: str
    target_hash: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    entry_hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "entry_index": self.entry_index,
            "timestamp_utc": self.timestamp_utc,
            "operator": self.operator,
            "scope_id": self.scope_id,
            "action": self.action,
            "outcome": self.outcome,
            "previous_hash": self.previous_hash,
            "target_hash": self.target_hash,
            "details": self.details,
        }
        canonical_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_index": self.entry_index,
            "timestamp_utc": self.timestamp_utc,
            "operator": self.operator,
            "scope_id": self.scope_id,
            "action": self.action,
            "target_hash": self.target_hash,
            "details": self.details,
            "outcome": self.outcome,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }


class AuditLogger:
    """Manages the append-only hash-chained audit log."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, log_path: str | Path, scope_id: str = "UNSCOPED"):
        self.log_path = Path(log_path)
        self.scope_id = scope_id
        try:
            self.operator = getpass.getuser()
        except Exception:
            self.operator = "analyst"
        self._last_hash = self.GENESIS_HASH
        self._last_index = -1
        self._init_chain()

    def _init_chain(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if self.log_path.exists() and self.log_path.stat().st_size > 0:
            # Read last entry
            with open(self.log_path, "r", encoding="utf-8") as f:
                last_line = ""
                count = 0
                for line in f:
                    line = line.strip()
                    if line:
                        last_line = line
                        count += 1
                if last_line:
                    data = json.loads(last_line)
                    self._last_hash = data["entry_hash"]
                    self._last_index = data["entry_index"]

    def log(
        self,
        action: str,
        outcome: str = "SUCCESS",
        target_hash: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        new_index = self._last_index + 1
        now_utc = datetime.now(timezone.utc).isoformat()
        entry = AuditEntry(
            entry_index=new_index,
            timestamp_utc=now_utc,
            operator=self.operator,
            scope_id=self.scope_id,
            action=action,
            outcome=outcome,
            previous_hash=self._last_hash,
            target_hash=target_hash,
            details=details or {},
        )
        entry.entry_hash = entry.compute_hash()

        # Append to log file
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")

        self._last_hash = entry.entry_hash
        self._last_index = new_index
        return entry


def verify_audit_chain(log_path: str | Path) -> Tuple[bool, Optional[int], str]:
    """Verifies the cryptographic integrity of an audit log.

    Returns:
        (is_valid, first_broken_index, message)
    """
    p = Path(log_path)
    if not p.exists():
        return False, None, f"Audit log does not exist: {p}"

    expected_prev = AuditLogger.GENESIS_HASH
    index = 0

    with open(p, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except Exception as e:
                return False, index, f"Malformed JSON on line {line_num}: {e}"

            entry = AuditEntry(
                entry_index=data.get("entry_index", -1),
                timestamp_utc=data.get("timestamp_utc", ""),
                operator=data.get("operator", ""),
                scope_id=data.get("scope_id", ""),
                action=data.get("action", ""),
                outcome=data.get("outcome", ""),
                previous_hash=data.get("previous_hash", ""),
                target_hash=data.get("target_hash"),
                details=data.get("details", {}),
                entry_hash=data.get("entry_hash", ""),
            )

            # Check index continuity
            if entry.entry_index != index:
                return False, index, f"Index mismatch at line {line_num}: expected {index}, got {entry.entry_index}"

            # Check previous hash link
            if entry.previous_hash != expected_prev:
                return False, index, (
                    f"Broken hash chain at entry {index} (line {line_num}): "
                    f"expected previous {expected_prev}, got {entry.previous_hash}"
                )

            # Check self entry hash
            computed = entry.compute_hash()
            if entry.entry_hash != computed:
                return False, index, (
                    f"Tampered entry content at entry {index} (line {line_num}): "
                    f"stored hash {entry.entry_hash} != computed hash {computed}"
                )

            expected_prev = entry.entry_hash
            index += 1

    if index == 0:
        return True, None, "Audit log is empty (valid)."

    return True, None, f"Audit chain verified successfully ({index} entries)."
