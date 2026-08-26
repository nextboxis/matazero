"""Composite encoder fingerprint computation per SRD FR-3.6."""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from imgint.core.fingerprint.dqt import QuantizationTable
from imgint.core.fingerprint.dht import HuffmanTable
from imgint.core.fingerprint.subsampling import ChromaSubsamplingInfo


@dataclass
class EncoderFingerprint:
    format_name: str
    dqt_tables: List[QuantizationTable] = field(default_factory=list)
    dht_tables: List[HuffmanTable] = field(default_factory=list)
    subsampling: Optional[ChromaSubsamplingInfo] = None
    segment_sequence: List[str] = field(default_factory=list)
    restart_interval: Optional[int] = None
    composite_hash: str = ""

    def compute_composite_hash(self) -> str:
        dqt_hashes = [t.table_hash for t in sorted(self.dqt_tables, key=lambda t: t.table_id)]
        dht_hashes = [h.table_hash for h in sorted(self.dht_tables, key=lambda h: (h.table_class, h.destination_id))]
        subsampling_str = self.subsampling.notation if self.subsampling else "None"
        seg_str = ",".join(self.segment_sequence)
        dri_str = str(self.restart_interval) if self.restart_interval is not None else "0"

        canonical = (
            f"FMT:{self.format_name}|DQT:{','.join(dqt_hashes)}|"
            f"DHT:{','.join(dht_hashes)}|SUB:{subsampling_str}|"
            f"SEG:{seg_str}|DRI:{dri_str}"
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format_name,
            "composite_hash": self.composite_hash,
            "dqt_count": len(self.dqt_tables),
            "estimated_qualities": [t.estimated_quality for t in self.dqt_tables if t.estimated_quality is not None],
            "dht_count": len(self.dht_tables),
            "subsampling": self.subsampling.notation if self.subsampling else None,
            "restart_interval": self.restart_interval,
            "segment_sequence": self.segment_sequence,
        }


class CompositeFingerprintBuilder:
    """Builds a composite encoder fingerprint from parsed structures."""

    @staticmethod
    def build(
        format_name: str,
        dqt_tables: List[QuantizationTable],
        dht_tables: List[HuffmanTable],
        subsampling: Optional[ChromaSubsamplingInfo],
        segment_sequence: List[str],
        restart_interval: Optional[int] = None,
    ) -> EncoderFingerprint:
        fp = EncoderFingerprint(
            format_name=format_name,
            dqt_tables=dqt_tables,
            dht_tables=dht_tables,
            subsampling=subsampling,
            segment_sequence=segment_sequence,
            restart_interval=restart_interval,
        )
        fp.composite_hash = fp.compute_composite_hash()
        return fp
