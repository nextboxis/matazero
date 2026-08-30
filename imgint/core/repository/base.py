"""Abstract Evidence Repository interface for storing and retrieving forensic records."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from imgint.core.model.record import AnalysisRecord


class EvidenceRepository(ABC):
    """Abstract repository for persisting and querying forensic AnalysisRecords."""

    @abstractmethod
    def save(self, record: AnalysisRecord) -> None:
        """Persists or updates an analysis record."""
        ...

    @abstractmethod
    def get_by_sha256(self, sha256: str) -> Optional[AnalysisRecord]:
        """Retrieves a record by whole-file SHA-256 hash."""
        ...

    @abstractmethod
    def list_all(self, limit: int = 100, offset: int = 0) -> List[AnalysisRecord]:
        """Lists stored records with pagination."""
        ...

    @abstractmethod
    def count(self) -> int:
        """Returns total count of stored evidence records."""
        ...

    @abstractmethod
    def delete(self, sha256: str) -> bool:
        """Deletes a record from storage."""
        ...
