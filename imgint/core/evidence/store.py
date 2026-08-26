"""Immutable Evidence Store and Custody Verification per SRD GR-2.1 - GR-2.8."""

from __future__ import annotations
import hashlib
import json
import os
import shutil
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class EvidenceCustodyError(Exception):
    """Raised when an evidence file hash changes or chain of custody is violated (Exit 7)."""
    pass


@dataclass
class IngestedEvidence:
    original_source_path: str
    stored_original_path: str
    working_copy_path: str
    sha256: str
    file_size: int
    ingest_timestamp_utc: str
    verified: bool = False


class EvidenceStore:
    """Manages immutable evidence files, working copies, and hash verification."""

    def __init__(self, root_dir: str | Path):
        self.root_dir = Path(root_dir)
        self.originals_dir = self.root_dir / "originals"
        self.working_dir = self.root_dir / "working"
        self.manifest_path = self.root_dir / "manifest.json"
        self.items: Dict[str, IngestedEvidence] = {}
        self._init_store()

    def _init_store(self) -> None:
        self.originals_dir.mkdir(parents=True, exist_ok=True)
        self.working_dir.mkdir(parents=True, exist_ok=True)
        if self.manifest_path.exists():
            try:
                with open(self.manifest_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data.get("items", []):
                        ev = IngestedEvidence(**item)
                        self.items[ev.sha256] = ev
            except Exception:
                pass

    @staticmethod
    def compute_sha256(file_path: str | Path) -> str:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def ingest(self, source_path: str | Path) -> IngestedEvidence:
        src = Path(source_path).resolve()
        if not src.exists():
            raise FileNotFoundError(f"Evidence file does not exist: {src}")

        # GR-2.1: Compute SHA-256 before any other processing
        file_hash = self.compute_sha256(src)
        file_size = src.stat().st_size
        ext = src.suffix or ".bin"
        now_utc = datetime.now(timezone.utc).isoformat()

        dest_original = self.originals_dir / f"{file_hash}{ext}"
        dest_working = self.working_dir / f"{file_hash}{ext}"

        # GR-2.2: Make original read-only
        if not dest_original.exists():
            shutil.copy2(src, dest_original)
            # Remove write permissions to protect original
            try:
                dest_original.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
            except Exception:
                pass

        # Create fresh working copy
        shutil.copy2(src, dest_working)
        # Ensure working copy is readable
        try:
            dest_working.chmod(stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP | stat.S_IROTH)
        except Exception:
            pass

        ev = IngestedEvidence(
            original_source_path=str(src),
            stored_original_path=str(dest_original),
            working_copy_path=str(dest_working),
            sha256=file_hash,
            file_size=file_size,
            ingest_timestamp_utc=now_utc,
            verified=True,
        )
        self.items[file_hash] = ev
        self._save_manifest()
        return ev

    def verify_all_originals(self) -> None:
        """GR-2.3: Re-verifies all original file hashes. Raises EvidenceCustodyError on mismatch."""
        for file_hash, ev in self.items.items():
            orig_path = Path(ev.stored_original_path)
            if not orig_path.exists():
                raise EvidenceCustodyError(
                    f"Evidence custody failure: original file missing: {orig_path}"
                )
            recomputed = self.compute_sha256(orig_path)
            if recomputed != file_hash:
                raise EvidenceCustodyError(
                    f"CRITICAL CUSTODY BREACH: Original file {orig_path} was modified! "
                    f"Expected hash {file_hash}, but found {recomputed}."
                )

    def _save_manifest(self) -> None:
        manifest_data = {
            "version": "2.0.0",
            "updated_utc": datetime.now(timezone.utc).isoformat(),
            "items": [
                {
                    "original_source_path": ev.original_source_path,
                    "stored_original_path": ev.stored_original_path,
                    "working_copy_path": ev.working_copy_path,
                    "sha256": ev.sha256,
                    "file_size": ev.file_size,
                    "ingest_timestamp_utc": ev.ingest_timestamp_utc,
                    "verified": ev.verified,
                }
                for ev in self.items.values()
            ],
        }
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)
