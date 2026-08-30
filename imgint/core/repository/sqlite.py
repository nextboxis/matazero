"""SQLite-backed Evidence Repository implementation."""

from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from typing import List, Optional

from imgint.core.model.record import AnalysisRecord
from imgint.core.repository.base import EvidenceRepository
from imgint.core.export.sqlite_exporter import SqliteExporter


class SqliteEvidenceRepository(EvidenceRepository):
    """Stores and queries forensic analysis records in an embedded SQLite database."""

    def __init__(self, db_path: str | Path = "./evidence_store/vault.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        SqliteExporter.export([], self.db_path)

    def save(self, record: AnalysisRecord) -> None:
        SqliteExporter.export([record], self.db_path)

    def get_by_sha256(self, sha256: str) -> Optional[AnalysisRecord]:
        conn = sqlite3.connect(str(self.db_path))
        cur = conn.cursor()
        cur.execute("SELECT sha256, file_name, file_path, mime_type FROM images WHERE sha256 = ?", (sha256,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        return AnalysisRecord(
            file_path=row[2],
            file_size=0,
            mime_type=row[3],
            sha256=row[0],
            tool_version="2.0.0",
            corpus_version="2026.08",
        )

    def list_all(self, limit: int = 100, offset: int = 0) -> List[AnalysisRecord]:
        conn = sqlite3.connect(str(self.db_path))
        cur = conn.cursor()
        cur.execute("SELECT sha256, file_name, file_path, mime_type FROM images LIMIT ? OFFSET ?", (limit, offset))
        rows = cur.fetchall()
        conn.close()
        return [
            AnalysisRecord(
                file_path=r[2],
                file_size=0,
                mime_type=r[3],
                sha256=r[0],
                tool_version="2.0.0",
                corpus_version="2026.08",
            )
            for r in rows
        ]

    def count(self) -> int:
        conn = sqlite3.connect(str(self.db_path))
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM images")
        val = cur.fetchone()[0]
        conn.close()
        return val

    def delete(self, sha256: str) -> bool:
        conn = sqlite3.connect(str(self.db_path))
        cur = conn.cursor()
        cur.execute("DELETE FROM images WHERE sha256 = ?", (sha256,))
        deleted = cur.rowcount > 0
        conn.commit()
        conn.close()
        return deleted
