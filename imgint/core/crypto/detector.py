"""Forensic Detection and Heuristic Classification of Encrypted and Scrambled Images."""

from __future__ import annotations
import math
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Any, List, Optional

import numpy as np
from PIL import Image

from imgint.core.crypto.ciphers import MATA_CONTAINER_MAGIC


@dataclass
class EncryptionDetectionResult:
    target_file: str
    is_encrypted: bool
    cipher_hint: str
    confidence_score: float
    spatial_gradient: float
    bitplane_entropy_profile: Dict[str, float]
    indicators: List[str] = field(default_factory=list)
    suggested_action: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EncryptionDetector:
    """Detects whether an image is encrypted, scrambled, or contains high-entropy payloads."""

    @classmethod
    def analyze_file(cls, file_path: str | Path) -> EncryptionDetectionResult:
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {p}")

        raw_bytes = p.read_bytes()
        indicators: List[str] = []

        # Check for matazero forensic container
        if raw_bytes.startswith(MATA_CONTAINER_MAGIC):
            return EncryptionDetectionResult(
                target_file=str(p),
                is_encrypted=True,
                cipher_hint="AES_CONTAINER",
                confidence_score=1.0,
                spatial_gradient=85.3,
                bitplane_entropy_profile={},
                indicators=["Valid matazero cryptographic container header detected (MATA_ENC)."],
                suggested_action=f"matazero decrypt '{p}' -p <password>",
            )

        # Check for PNG deBG chunk or other custom markers
        has_debg_chunk = b"deBG" in raw_bytes[:1000] or b"deBG" in raw_bytes[-1000:]
        if has_debg_chunk:
            indicators.append("Private 'deBG' metadata marker identified; consistent with web-based scrambled image.")

        try:
            img = Image.open(p)
            img_rgb = img.convert("RGB")
            arr = np.array(img_rgb)
        except Exception as e:
            return EncryptionDetectionResult(
                target_file=str(p),
                is_encrypted=False,
                cipher_hint="UNKNOWN_FORMAT",
                confidence_score=0.0,
                spatial_gradient=0.0,
                bitplane_entropy_profile={},
                indicators=[f"Unable to parse image raster: {e}"],
            )

        # Sample raster if image is very large for quick evaluation
        h, w, c = arr.shape
        step_h = max(1, h // 512)
        step_w = max(1, w // 512)
        sample = arr[::step_h, ::step_w, :]

        # 1. Spatial Gradient Analysis
        # Natural images: diff between adjacent horizontal pixels is small (~5-25)
        # Encrypted / uniform random noise: mean absolute diff is ~85.33
        horiz_diff = np.abs(sample.astype(np.int32)[:, 1:, :] - sample.astype(np.int32)[:, :-1, :]).mean()
        vert_diff = np.abs(sample.astype(np.int32)[1:, :, :] - sample.astype(np.int32)[:-1, :, :]).mean()
        gradient = float((horiz_diff + vert_diff) / 2.0)

        # 2. Bitplane Shannon Entropy across channels
        bitplane_entropies: Dict[str, float] = {}
        for plane in [0, 1, 6, 7]:
            bits = (sample >> plane) & 1
            p1 = float(np.mean(bits))
            p0 = 1.0 - p1
            if p0 > 0 and p1 > 0:
                ent = - (p0 * math.log2(p0) + p1 * math.log2(p1))
            else:
                ent = 0.0
            bitplane_entropies[f"plane_{plane}"] = round(ent, 4)

        msb_ent = (bitplane_entropies.get("plane_7", 0.0) + bitplane_entropies.get("plane_6", 0.0)) / 2.0
        lsb_ent = (bitplane_entropies.get("plane_0", 0.0) + bitplane_entropies.get("plane_1", 0.0)) / 2.0

        is_encrypted = False
        cipher_hint = "CLEAN_NATURAL"
        confidence = 0.1
        suggested_action = None

        # Evaluation Heuristics
        if gradient >= 80.0 and msb_ent > 0.98 and lsb_ent > 0.98:
            is_encrypted = True
            confidence = 0.95
            cipher_hint = "MULBERRY32_OR_AES_PIXEL"
            indicators.append(
                f"Near-maximum spatial gradient variance ({gradient:.2f}/85.33) and uniform high entropy across all bitplanes (MSB H={msb_ent:.4f}, LSB H={lsb_ent:.4f}). Image is completely scrambled or encrypted."
            )
            suggested_action = f"matazero decrypt '{p}' -p <password>  (or --brute-force)"
        elif gradient >= 70.0 and msb_ent > 0.95:
            is_encrypted = True
            confidence = 0.75
            cipher_hint = "SCRAMBLED_IMAGE"
            indicators.append(f"Elevated spatial gradient variance ({gradient:.2f}) and high MSB entropy ({msb_ent:.4f}).")
            suggested_action = f"matazero decrypt '{p}' -p <password>"
        elif lsb_ent > 0.99 and msb_ent < 0.75:
            is_encrypted = False
            cipher_hint = "LSB_COVERT_STEGO"
            confidence = 0.80
            indicators.append(f"Sharp entropy discontinuity between MSB ({msb_ent:.4f}) and LSB ({lsb_ent:.4f}). Covert steganographic carrier suspected.")
            suggested_action = f"matazero stego '{p}' --extract -p <password>"
        else:
            indicators.append(f"Normal spatial continuity ({gradient:.2f}) and natural bitplane entropy distribution.")

        return EncryptionDetectionResult(
            target_file=str(p),
            is_encrypted=is_encrypted,
            cipher_hint=cipher_hint,
            confidence_score=round(confidence, 2),
            spatial_gradient=round(gradient, 2),
            bitplane_entropy_profile=bitplane_entropies,
            indicators=indicators,
            suggested_action=suggested_action,
        )

    @classmethod
    def detect_image(cls, image: Image.Image) -> Dict[str, Any]:
        """Directly analyzes an in-memory PIL Image object."""
        img_rgb = image.convert("RGB")
        arr = np.array(img_rgb)
        h, w, c = arr.shape
        step_h = max(1, h // 512)
        step_w = max(1, w // 512)
        sample = arr[::step_h, ::step_w, :]

        horiz_diff = np.abs(sample.astype(np.int32)[:, 1:, :] - sample.astype(np.int32)[:, :-1, :]).mean()
        vert_diff = np.abs(sample.astype(np.int32)[1:, :, :] - sample.astype(np.int32)[:-1, :, :]).mean()
        gradient = float((horiz_diff + vert_diff) / 2.0)

        bitplane_entropies: Dict[str, float] = {}
        for plane in [0, 1, 6, 7]:
            bits = (sample >> plane) & 1
            p1 = float(np.mean(bits))
            p0 = 1.0 - p1
            if p0 > 0 and p1 > 0:
                ent = - (p0 * math.log2(p0) + p1 * math.log2(p1))
            else:
                ent = 0.0
            bitplane_entropies[f"plane_{plane}"] = round(ent, 4)

        msb_ent = (bitplane_entropies.get("plane_7", 0.0) + bitplane_entropies.get("plane_6", 0.0)) / 2.0
        lsb_ent = (bitplane_entropies.get("plane_0", 0.0) + bitplane_entropies.get("plane_1", 0.0)) / 2.0

        is_encrypted = gradient >= 70.0 and msb_ent > 0.95
        confidence = 0.95 if gradient >= 80.0 else (0.75 if is_encrypted else 0.1)

        return {
            "is_encrypted": is_encrypted,
            "confidence_score": confidence,
            "gradient_diff": round(gradient, 2),
            "bitplane_entropy": bitplane_entropies,
            "msb_entropy": round(msb_ent, 4),
            "lsb_entropy": round(lsb_ent, 4),
        }

