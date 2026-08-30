"""Repository and Unit-of-Work pattern for evidence persistence."""

from imgint.core.repository.base import EvidenceRepository
from imgint.core.repository.filesystem import FilesystemEvidenceRepository
from imgint.core.repository.sqlite import SqliteEvidenceRepository

__all__ = [
    "EvidenceRepository",
    "FilesystemEvidenceRepository",
    "SqliteEvidenceRepository",
]
