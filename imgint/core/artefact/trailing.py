"""Trailing data detection and payload type sniffing per SRD FR-4.5."""

from __future__ import annotations
import math
from collections import Counter
from dataclasses import dataclass
from typing import Optional
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import StructuralUnit


@dataclass
class TrailingDataInfo:
    offset: int
    length: int
    shannon_entropy: float
    detected_payload_type: str  # "ZIP Archive", "RAR Archive", "Executable (PE/ELF)", "Plain Text", "Encrypted / Random Bytes", etc.
    preview_hex: str


class TrailingDataExtractor:
    """Analyzes trailing bytes appended past image datastream boundaries (FFD9 / IEND)."""

    @staticmethod
    def analyze(trailing_unit: StructuralUnit, full_data: bytes) -> TrailingDataInfo:
        offset = trailing_unit.offset
        length = trailing_unit.length
        raw_slice = full_data[offset : offset + length]

        entropy = TrailingDataExtractor.compute_shannon_entropy(raw_slice)
        payload_type = TrailingDataExtractor.sniff_payload_type(raw_slice, entropy)

        preview = raw_slice[:32].hex(" ").upper()
        return TrailingDataInfo(
            offset=offset,
            length=length,
            shannon_entropy=round(entropy, 3),
            detected_payload_type=payload_type,
            preview_hex=preview,
        )

    @staticmethod
    def compute_shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def sniff_payload_type(data: bytes, entropy: float) -> str:
        if len(data) >= 4 and data[:4] == b"PK\x03\x04":
            return "ZIP Archive / Polyglot"
        if len(data) >= 7 and data[:7] == b"Rar!\x1a\x07\x00":
            return "RAR Archive"
        if len(data) >= 6 and data[:6] == b"7z\xbc\xaf\x27\x1c":
            return "7-Zip Archive"
        if len(data) >= 2 and data[:2] == b"MZ":
            return "Windows Executable / DLL (MZ header)"
        if len(data) >= 4 and data[:4] == b"\x7fELF":
            return "Linux ELF Binary"
        if len(data) >= 3 and data[:3] == b"\x1f\x8b\x08":
            return "GZIP Compressed Stream"

        # Check if plain text
        try:
            sample = data[:min(len(data), 256)].decode("ascii")
            if all(c.isprintable() or c in "\r\n\t " for c in sample):
                return "Plaintext String / Script"
        except Exception:
            pass

        if entropy > 7.5:
            return "High-Entropy Data (Encrypted / Compressed / Steganographic Carrier)"
        elif entropy < 2.0:
            return "Low-Entropy Data (Zero Padding / Repetitive Pattern)"
        else:
            return "Structured Binary Payload"
