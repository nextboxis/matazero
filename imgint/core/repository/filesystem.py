"""Filesystem-backed Evidence Repository implementation."""

from __future__ import annotations
import json
from pathlib import Path
from typing import List, Optional

from imgint.core.model.record import AnalysisRecord
from imgint.core.repository.base import EvidenceRepository
from imgint.core.report.renderer import ReportRenderer


class FilesystemEvidenceRepository(EvidenceRepository):
    """Stores and queries forensic analysis records as JSON files on the local filesystem."""

    def __init__(self, root_dir: str | Path = "./evidence_store") -> None:
        self.root_dir = Path(root_dir)
        self.records_dir = self.root_dir / "records"
        self.records_dir.mkdir(parents=True, exist_ok=True)

    def save(self, record: AnalysisRecord) -> None:
        dest_file = self.records_dir / f"{record.sha256}.json"
        dest_file.write_text(ReportRenderer.render_json([record]), encoding="utf-8")

    def get_by_sha256(self, sha256: str) -> Optional[AnalysisRecord]:
        target_file = self.records_dir / f"{sha256}.json"
        if not target_file.exists():
            return None
        try:
            # Load from JSON file
            data = json.loads(target_file.read_text(encoding="utf-8"))
            if isinstance(data, list) and len(data) > 0:
                data = data[0]
            # Reconstruct basic AnalysisRecord
            rec = AnalysisRecord(
                file_path=data.get("file_path", ""),
                file_size=data.get("file_size", 0),
                mime_type=data.get("mime_type", "application/octet-stream"),
                sha256=data.get("sha256", sha256),
                tool_version=data.get("tool_version", "2.0.0"),
                corpus_version=data.get("corpus_version", "2026.08"),
            )
            return rec
        except Exception:
            return None

    def list_all(self, limit: int = 100, offset: int = 0) -> List[AnalysisRecord]:
        files = sorted(self.records_dir.glob("*.json"))[offset:offset + limit]
        records = []
        for f in files:
            rec = self.get_by_sha256(f.stem)
            if rec:
                records.append(rec)
        return records

    def count(self) -> int:
        return len(list(self.records_dir.glob("*.json")))

    def delete(self, sha256: str) -> bool:
        target_file = self.records_dir / f"{sha256}.json"
        if target_file.exists():
            target_file.unlink()
            return True
        return False
