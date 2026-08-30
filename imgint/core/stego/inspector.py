"""Steganography, bitplane slicing, and statistical anomaly inspector."""

from __future__ import annotations
import math
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from imgint.core.sandbox.process import SandboxRunner


@dataclass
class StegoAnalysisResult:
    target_file: str
    file_size_bytes: int
    dimensions: Dict[str, Any]
    bitplane_entropies: Dict[str, Dict[str, Any]]
    chi_square_stats: Dict[str, Any]
    lsb_bit_density: float
    stego_risk_score: float  # 0.0 (Clean) to 1.0 (High Probability Stego)
    stego_verdict: str
    risk_level: str  # "LOW", "MEDIUM", "HIGH"
    indicators: List[str]
    saved_bitplane_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class StegoInspector:
    """Performs deep multi-channel bitplane slicing, Chi-Square PoV attacks, and LSB analysis."""

    @classmethod
    def inspect(
        cls,
        target_path: str | Path,
        save_bitplanes_dir: Optional[str | Path] = None,
    ) -> StegoAnalysisResult:
        p = Path(target_path)
        size_bytes = p.stat().st_size

        # Run sandboxed decode tasks
        sandbox_res = SandboxRunner.run_decode_tasks(
            str(p),
            tasks=["dimensions", "entropy", "chi_square", "bitplane_slice"]
        )

        if not sandbox_res.get("success"):
            raise RuntimeError(f"Sandboxed steganography inspection failed: {sandbox_res.get('error')}")

        tasks = sandbox_res.get("tasks", {})
        dims = tasks.get("dimensions", {})
        entropy_data = tasks.get("entropy", {})
        chi_data = tasks.get("chi_square", {})
        bitplane_data = tasks.get("bitplane_slice", {})

        lsb_density = entropy_data.get("lsb_bit_density", 0.5)

        # Calculate Stego Risk Indicators
        indicators: List[str] = []
        risk_score = 0.1

        # 1. Evaluate LSB Shannon entropy across channels
        # Natural images have lower entropy in LSBs than encrypted/compressed payloads (which hover around 1.0)
        high_entropy_lsb_channels = []
        for ch, planes in bitplane_data.items():
            plane_0 = planes.get("plane_0", {})
            ent = plane_0.get("entropy", 0.0)
            density = plane_0.get("bit_density", 0.5)
            if ent > 0.99 and 0.45 <= density <= 0.55:
                high_entropy_lsb_channels.append(ch)

        if len(high_entropy_lsb_channels) >= 2:
            risk_score += 0.35
            indicators.append(
                f"Maximum LSB Shannon entropy (H > 0.99) and 50% density across {', '.join(high_entropy_lsb_channels)} channels (indicative of pseudo-random encrypted payload)."
            )
        elif len(high_entropy_lsb_channels) == 1:
            risk_score += 0.15
            indicators.append(
                f"High LSB Shannon entropy in {high_entropy_lsb_channels[0]} channel."
            )

        # 2. Evaluate Chi-Square Pair-of-Values (PoV)
        uniform_pov_channels = []
        for ch, stat in chi_data.items():
            if stat.get("uniform_lsb_pairing_suspected"):
                uniform_pov_channels.append(ch)

        if uniform_pov_channels:
            risk_score += 0.4
            indicators.append(
                f"Chi-Square Pair-of-Values test indicates artificial LSB equalization in {', '.join(uniform_pov_channels)} channels (PoV p-value anomaly)."
            )

        # 3. Bitplane Progression Gradient
        # Natural photos have a smooth gradient: Plane 7 (MSB, low entropy) -> Plane 0 (LSB, moderate entropy)
        # Steganography exhibits sudden entropy spikes in Plane 0 or 1.
        for ch, planes in bitplane_data.items():
            ent_0 = planes.get("plane_0", {}).get("entropy", 0.0)
            ent_1 = planes.get("plane_1", {}).get("entropy", 0.0)
            if ent_0 > 0.98 and ent_1 < 0.70:
                risk_score += 0.2
                indicators.append(
                    f"Sharp entropy discontinuity between Plane 0 (H={ent_0}) and Plane 1 (H={ent_1}) in {ch} channel."
                )

        risk_score = max(0.0, min(1.0, risk_score))

        if risk_score >= 0.7:
            verdict = "SUSPECTED_COVERT_STEGANOGRAPHY"
            risk_level = "HIGH"
        elif risk_score >= 0.4:
            verdict = "POSSIBLE_LSB_MANIPULATION"
            risk_level = "MEDIUM"
        else:
            verdict = "CLEAN_NATURAL_ENTROPY"
            risk_level = "LOW"
            if not indicators:
                indicators.append("Normal natural spatial variance; no artificial LSB pairing or entropy spikes detected.")

        # Save bitplanes if requested
        saved_files = []
        if save_bitplanes_dir:
            out_dir = Path(save_bitplanes_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            saved_files = cls._export_bitplane_images(p, out_dir)

        return StegoAnalysisResult(
            target_file=str(p),
            file_size_bytes=size_bytes,
            dimensions=dims,
            bitplane_entropies=bitplane_data,
            chi_square_stats=chi_data,
            lsb_bit_density=lsb_density,
            stego_risk_score=round(risk_score, 2),
            stego_verdict=verdict,
            risk_level=risk_level,
            indicators=indicators,
            saved_bitplane_files=saved_files,
        )

    @classmethod
    def _export_bitplane_images(cls, src_path: Path, out_dir: Path) -> List[str]:
        saved = []
        try:
            from PIL import Image
            import numpy as np
            img = Image.open(src_path).convert("RGB")
            arr = np.array(img)
            base_name = src_path.stem

            for c_idx, c_name in enumerate(["red", "green", "blue"]):
                for p in [0, 7]:  # Export LSB (0) and MSB (7)
                    bit_plane = ((arr[..., c_idx] >> p) & 1) * 255
                    plane_img = Image.fromarray(bit_plane.astype(np.uint8), mode="L")
                    f_name = f"{base_name}_{c_name}_plane{p}.png"
                    dest = out_dir / f_name
                    plane_img.save(dest)
                    saved.append(str(dest))
        except Exception:
            pass
        return saved
