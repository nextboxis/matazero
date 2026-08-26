"""JPEG DHT Huffman table extractor and classification per SRD FR-3.2."""

from __future__ import annotations
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Tuple

# Standard ISO/IEC 10918-1 baseline DC and AC luminance/chrominance tables counts
STD_LUMINANCE_DC_COUNTS = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
STD_CHROMINANCE_DC_COUNTS = [0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0]


@dataclass
class HuffmanTable:
    table_class: int  # 0 = DC, 1 = AC
    destination_id: int  # 0 = Luminance, 1 = Chrominance
    counts: List[int]
    symbols: List[int]
    is_standard: bool
    table_hash: str
    class_name: str


class DhtExtractor:
    """Extracts Huffman tables from JPEG DHT segments and classifies default vs optimized."""

    @staticmethod
    def extract_from_dht_payload(payload: bytes) -> List[HuffmanTable]:
        tables: List[HuffmanTable] = []
        offset = 0
        size = len(payload)

        while offset < size:
            info_byte = payload[offset]
            destination_id = info_byte & 0x0F
            table_class = (info_byte >> 4) & 0x0F
            offset += 1

            if offset + 16 > size:
                break

            counts = list(payload[offset : offset + 16])
            offset += 16

            symbol_count = sum(counts)
            if offset + symbol_count > size:
                break

            symbols = list(payload[offset : offset + symbol_count])
            offset += symbol_count

            # Compare against standard baseline counts
            is_standard = False
            if table_class == 0:
                if destination_id == 0 and counts == STD_LUMINANCE_DC_COUNTS:
                    is_standard = True
                elif destination_id == 1 and counts == STD_CHROMINANCE_DC_COUNTS:
                    is_standard = True

            thash = hashlib.sha256(bytes(counts + symbols)).hexdigest()[:16]
            class_name = f"{'DC' if table_class == 0 else 'AC'}_{'Luminance' if destination_id == 0 else 'Chrominance'}"

            tables.append(
                HuffmanTable(
                    table_class=table_class,
                    destination_id=destination_id,
                    counts=counts,
                    symbols=symbols,
                    is_standard=is_standard,
                    table_hash=thash,
                    class_name=class_name,
                )
            )

        return tables
