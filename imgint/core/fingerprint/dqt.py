"""JPEG DQT quantization table extractor and quality estimator per SRD FR-3.1."""

from __future__ import annotations
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Standard Independent JPEG Group (IJG) base luminance quantization table
IJG_LUMINANCE_BASE = [
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
]

# Standard IJG base chrominance quantization table
IJG_CHROMINANCE_BASE = [
    17, 18, 24, 47, 99, 99, 99, 99,
    18, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
]


@dataclass
class QuantizationTable:
    table_id: int
    precision: int  # 0 = 8-bit, 1 = 16-bit
    values: List[int]
    table_hash: str
    estimated_quality: Optional[int] = None
    table_type: str = "Unknown"  # "Luminance" (0), "Chrominance" (1), or "Custom"


class DqtExtractor:
    """Extracts Quantization Tables from JPEG DQT segments."""

    @staticmethod
    def extract_from_dqt_payload(payload: bytes) -> List[QuantizationTable]:
        tables: List[QuantizationTable] = []
        offset = 0
        size = len(payload)

        while offset < size:
            info_byte = payload[offset]
            table_id = info_byte & 0x0F
            precision = (info_byte >> 4) & 0x0F
            offset += 1

            element_size = 2 if precision == 1 else 1
            table_bytes_len = 64 * element_size

            if offset + table_bytes_len > size:
                break

            table_bytes = payload[offset : offset + table_bytes_len]
            offset += table_bytes_len

            if precision == 0:
                values = list(table_bytes)
            else:
                values = [
                    int.from_bytes(table_bytes[i : i + 2], "big")
                    for i in range(0, 128, 2)
                ]

            thash = hashlib.sha256(table_bytes).hexdigest()[:16]
            table_type = "Luminance" if table_id == 0 else ("Chrominance" if table_id == 1 else f"Table_{table_id}")
            est_quality = DqtExtractor.estimate_quality(values, table_id)

            tables.append(
                QuantizationTable(
                    table_id=table_id,
                    precision=precision,
                    values=values,
                    table_hash=thash,
                    estimated_quality=est_quality,
                    table_type=table_type,
                )
            )

        return tables

    @staticmethod
    def estimate_quality(values: List[int], table_id: int) -> int:
        """Estimates JPEG quality setting (1-100) by comparing with IJG standard tables."""
        if len(values) < 64:
            return 50

        base = IJG_LUMINANCE_BASE if table_id == 0 else IJG_CHROMINANCE_BASE
        ratios = []
        for i in range(1, 16):  # Check low/mid frequencies
            if base[i] > 0 and values[i] > 0:
                ratios.append(values[i] / base[i])

        if not ratios:
            return 50

        avg_ratio = sum(ratios) / len(ratios)
        if avg_ratio <= 0:
            return 100

        # IJG quality formula:
        # If Q < 50: S = 5000 / Q => ratio = S / 100 = 50 / Q => Q = 50 / avg_ratio
        # If Q >= 50: S = 200 - 2 * Q => ratio = S / 100 => Q = (200 - 100 * avg_ratio) / 2 = 100 - 50 * avg_ratio
        if avg_ratio > 1.0:
            q = int(round(50.0 / avg_ratio))
        else:
            q = int(round(100.0 - 50.0 * avg_ratio))

        return max(1, min(100, q))
