"""Authorization Scope definition, verification, and enforcement per SRD GR-1.1 - GR-1.7."""

from __future__ import annotations
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from imgint.core.governance.refusals import enforce_refusals


class ScopeValidationError(Exception):
    """Raised when an authorization scope fails validation or is expired."""
    pass


@dataclass
class AuthorizationScope:
    case_id: str
    purpose: str
    legal_basis: str
    authorising_party: str
    data_subject_categories: List[str]
    permitted_operations: List[str]  # e.g., ["tier1", "tier2", "tier3", "tier4", "tier5", "tier6", "tier7"]
    retention_period_days: int
    expiry_date: str  # ISO 8601 UTC string
    disabled_analyzers: List[str] = field(default_factory=list)
    signature: Optional[str] = None
    scope_hash: Optional[str] = None
    is_self_audit: bool = False

    def __post_init__(self) -> None:
        if not self.is_self_audit:
            # Check for refused capabilities
            enforce_refusals(set(self.permitted_operations))

    @property
    def is_expired(self) -> bool:
        if self.is_self_audit:
            return False
        try:
            exp = datetime.fromisoformat(self.expiry_date.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            return now > exp
        except Exception:
            return True

    def is_analyzer_permitted(self, analyzer_id: str, tier: int) -> bool:
        if self.is_self_audit:
            # Self-audit allows privacy examination (tiers 1-4)
            return analyzer_id not in self.disabled_analyzers

        if analyzer_id in self.disabled_analyzers:
            return False
        tier_key = f"tier{tier}"
        if "all" in self.permitted_operations or tier_key in self.permitted_operations:
            return True
        if analyzer_id in self.permitted_operations:
            return True
        return False

    def compute_canonical_hash(self, secret_key: Optional[str] = None) -> str:
        payload = {
            "case_id": self.case_id,
            "purpose": self.purpose,
            "legal_basis": self.legal_basis,
            "authorising_party": self.authorising_party,
            "data_subject_categories": sorted(self.data_subject_categories),
            "permitted_operations": sorted(self.permitted_operations),
            "retention_period_days": self.retention_period_days,
            "expiry_date": self.expiry_date,
            "disabled_analyzers": sorted(self.disabled_analyzers),
        }
        canonical_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        if secret_key:
            return hmac.new(secret_key.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()
        return hashlib.sha256(canonical_bytes).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "purpose": self.purpose,
            "legal_basis": self.legal_basis,
            "authorising_party": self.authorising_party,
            "data_subject_categories": self.data_subject_categories,
            "permitted_operations": self.permitted_operations,
            "retention_period_days": self.retention_period_days,
            "expiry_date": self.expiry_date,
            "disabled_analyzers": self.disabled_analyzers,
            "signature": self.signature,
            "scope_hash": self.scope_hash,
            "is_self_audit": self.is_self_audit,
        }

    def save_to_file(self, path: str | Path, secret_key: Optional[str] = None) -> None:
        self.scope_hash = self.compute_canonical_hash()
        if secret_key:
            self.signature = self.compute_canonical_hash(secret_key=secret_key)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_from_file(cls, path: str | Path, secret_key: Optional[str] = None) -> AuthorizationScope:
        p = Path(path)
        if not p.exists():
            raise ScopeValidationError(f"Scope file not found at: {p}")
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise ScopeValidationError(f"Failed to read scope JSON: {e}")

        # Required fields check per GR-1.2
        required = [
            "case_id", "purpose", "legal_basis", "authorising_party",
            "data_subject_categories", "permitted_operations",
            "retention_period_days", "expiry_date"
        ]
        missing = [k for k in required if k not in data]
        if missing:
            raise ScopeValidationError(f"Invalid scope: missing required fields {missing}")

        scope = cls(
            case_id=data["case_id"],
            purpose=data["purpose"],
            legal_basis=data["legal_basis"],
            authorising_party=data["authorising_party"],
            data_subject_categories=data.get("data_subject_categories", []),
            permitted_operations=data.get("permitted_operations", []),
            retention_period_days=data.get("retention_period_days", 30),
            expiry_date=data["expiry_date"],
            disabled_analyzers=data.get("disabled_analyzers", []),
            signature=data.get("signature"),
            scope_hash=data.get("scope_hash"),
            is_self_audit=data.get("is_self_audit", False),
        )

        # Verify integrity
        expected_hash = scope.compute_canonical_hash()
        if scope.scope_hash and scope.scope_hash != expected_hash:
            raise ScopeValidationError("Scope integrity check failed: scope_hash does not match content.")

        if secret_key:
            expected_sig = scope.compute_canonical_hash(secret_key=secret_key)
            if scope.signature != expected_sig:
                raise ScopeValidationError("Scope signature verification failed: invalid signature.")

        # Check expiry per GR-1.3
        if scope.is_expired:
            raise ScopeValidationError(
                f"Authorization scope expired on {scope.expiry_date}. "
                "Per GR-1.3, operation is refused with no override."
            )

        if not scope.scope_hash:
            scope.scope_hash = expected_hash

        return scope

    @classmethod
    def create_self_audit_scope(cls) -> AuthorizationScope:
        """Creates a narrow scope for --self-audit mode per GR-1.7."""
        return cls(
            case_id="SELF_AUDIT",
            purpose="Personal privacy audit of user-owned files",
            legal_basis="User Consent (Own Files)",
            authorising_party="User",
            data_subject_categories=["User"],
            permitted_operations=["tier1", "tier2", "tier3", "tier4"],
            retention_period_days=0,
            expiry_date="2099-01-01T00:00:00Z",
            is_self_audit=True,
            scope_hash="self_audit_mode",
        )
