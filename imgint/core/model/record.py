"""Analysis records, diagnostics, structural units, metadata blocks, and resource budgets."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from imgint.core.model.finding import Finding


@dataclass
class Diagnostic:
    level: str  # "info", "warning", "error"
    message: str
    source: str
    offset: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "level": self.level,
            "message": self.message,
            "source": self.source,
        }
        if self.offset is not None:
            d["offset"] = self.offset
        return d


@dataclass
class StructuralUnit:
    name: str
    offset: int
    length: int
    data_offset: int
    data_length: int
    description: Optional[str] = None
    payload: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "offset": self.offset,
            "length": self.length,
            "data_offset": self.data_offset,
            "data_length": self.data_length,
        }
        if self.description:
            d["description"] = self.description
        return d


@dataclass
class MetadataBlock:
    kind: str  # "EXIF", "XMP", "IPTC", "ICC", "C2PA", "PNG_TEXT", "JFIF", etc.
    offset: int
    length: int
    raw_bytes: bytes
    source_unit: Optional[str] = None


@dataclass
class Field:
    standard: str  # "EXIF", "XMP", "IPTC", "ICC", "PNG", etc.
    name: str
    value: Any
    raw_value: Any
    value_type: str
    tag_id: Optional[str] = None
    description: Optional[str] = None
    offset: Optional[int] = None        # Tag entry / header offset in file
    value_offset: Optional[int] = None  # Offset where value bytes actually reside in file
    length: Optional[int] = None        # Byte length of value data

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "standard": self.standard,
            "name": self.name,
            "value": self.value,
            "value_type": self.value_type,
        }
        if self.tag_id:
            d["tag_id"] = self.tag_id
        if self.description:
            d["description"] = self.description
        if self.offset is not None:
            d["offset"] = self.offset
        if self.value_offset is not None:
            d["value_offset"] = self.value_offset
        if self.length is not None:
            d["length"] = self.length
        return d



@dataclass
class ResourceBudget:
    max_depth: int = 16
    max_units: int = 4096
    max_decompressed_bytes: int = 16 * 1024 * 1024  # 16 MB
    max_time_seconds: float = 10.0
    max_memory_mb: int = 256


@dataclass
class AnalysisRecord:
    file_path: str
    file_size: int
    mime_type: str
    sha256: str
    tool_version: str
    corpus_version: str
    data_stream_sha256: Optional[str] = None
    scope_id: Optional[str] = None
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: List[Finding] = field(default_factory=list)
    diagnostics: List[Diagnostic] = field(default_factory=list)
    structural_units: List[StructuralUnit] = field(default_factory=list)
    metadata_blocks: List[MetadataBlock] = field(default_factory=list)
    fields: List[Field] = field(default_factory=list)
    not_established: List[str] = field(default_factory=list)
    authenticity_verdict: Optional[Dict[str, Any]] = None

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_diagnostic(self, level: str, message: str, source: str, offset: Optional[int] = None) -> None:
        self.diagnostics.append(Diagnostic(level=level, message=message, source=source, offset=offset))

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "schema_version": "2.0.0",
            "file_path": self.file_path,
            "file_size": self.file_size,
            "mime_type": self.mime_type,
            "sha256": self.sha256,
            "data_stream_sha256": self.data_stream_sha256,
            "scope_id": self.scope_id,
            "tool_version": self.tool_version,
            "corpus_version": self.corpus_version,
            "timestamp_utc": self.timestamp_utc,
            "not_established": self.not_established,
            "findings": [f.to_dict() for f in self.findings],
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "structural_units": [u.to_dict() for u in self.structural_units],
            "fields": [f.to_dict() for f in self.fields],
        }
        if self.authenticity_verdict is not None:
            d["authenticity_verdict"] = self.authenticity_verdict
        return d
