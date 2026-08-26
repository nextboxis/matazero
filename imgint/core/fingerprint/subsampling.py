"""Chroma subsampling extraction and classification from SOF segments per SRD FR-3.3."""

from __future__ import annotations
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class ChromaSubsamplingInfo:
    notation: str       # "4:4:4", "4:2:2", "4:2:0", "4:1:1", "Grayscale", etc.
    components_count: int
    precision_bits: int
    image_width: int
    image_height: int
    sampling_factors: Dict[int, Tuple[int, int]]  # Component ID -> (H, V)


class SubsamplingExtractor:
    """Extracts chroma subsampling and image dimensions from SOF0/SOF2 payloads."""

    @staticmethod
    def extract_from_sof_payload(payload: bytes) -> Optional[ChromaSubsamplingInfo]:
        if len(payload) < 6:
            return None

        precision = payload[0]
        height, width, num_components = struct.unpack(">HHB", payload[1:6])

        factors: Dict[int, Tuple[int, int]] = {}
        offset = 6
        for _ in range(num_components):
            if offset + 3 > len(payload):
                break
            comp_id = payload[offset]
            sampling = payload[offset + 1]
            h_samp = (sampling >> 4) & 0x0F
            v_samp = sampling & 0x0F
            factors[comp_id] = (h_samp, v_samp)
            offset += 3

        if num_components == 1:
            notation = "Grayscale (1-channel)"
        elif num_components >= 3 and 1 in factors and 2 in factors and 3 in factors:
            h1, v1 = factors[1]
            h2, v2 = factors[2]
            h3, v3 = factors[3]
            if (h1, v1) == (1, 1) and (h2, v2) == (1, 1):
                notation = "4:4:4"
            elif (h1, v1) == (2, 1) and (h2, v2) == (1, 1):
                notation = "4:2:2"
            elif (h1, v1) == (2, 2) and (h2, v2) == (1, 1):
                notation = "4:2:0"
            elif (h1, v1) == (4, 1) and (h2, v2) == (1, 1):
                notation = "4:1:1"
            elif (h1, v1) == (1, 2) and (h2, v2) == (1, 1):
                notation = "4:4:0"
            else:
                notation = f"Custom ({h1}x{v1}, {h2}x{v2}, {h3}x{v3})"
        else:
            notation = f"Multi-channel ({num_components})"

        return ChromaSubsamplingInfo(
            notation=notation,
            components_count=num_components,
            precision_bits=precision,
            image_width=width,
            image_height=height,
            sampling_factors=factors,
        )
