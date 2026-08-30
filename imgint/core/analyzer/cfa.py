"""Color Filter Array (CFA) Bayer Demosaicing Inconsistency Analyzer."""

from __future__ import annotations
import io
from typing import Any, Dict, Optional, Tuple
import numpy as np
from PIL import Image


class CfaDemosaicAnalyzer:
    """Analyzes Color Filter Array (CFA) Bayer interpolation periodicity in green/chroma channels."""

    @staticmethod
    def analyze(img_or_bytes: Image.Image | bytes | np.ndarray) -> Dict[str, Any]:
        if isinstance(img_or_bytes, bytes):
            img = Image.open(io.BytesIO(img_or_bytes)).convert("RGB")
        elif isinstance(img_or_bytes, np.ndarray):
            img = Image.fromarray(img_or_bytes.astype(np.uint8)).convert("RGB")
        else:
            img = img_or_bytes.convert("RGB")

        # Resize to standard analysis block (512x512) for reliable frequency analysis
        max_dim = 512
        w, h = img.size
        if w != max_dim or h != max_dim:
            # Crop center region to preserve raw pixel relationships without resampling distortion
            cw, ch = min(w, max_dim), min(h, max_dim)
            left = (w - cw) // 2
            top = (h - ch) // 2
            img_crop = img.crop((left, top, left + cw, top + ch))
        else:
            img_crop = img

        arr = np.array(img_crop, dtype=np.float32)
        if arr.shape[0] < 64 or arr.shape[1] < 64:
            return {
                "bayer_periodicity_score": 0.0,
                "cfa_pattern_detected": "UNKNOWN_TOO_SMALL",
                "is_hardware_sensor_consistent": False,
            }

        # Extract channels
        R = arr[:, :, 0]
        G = arr[:, :, 1]
        B = arr[:, :, 2]

        # Estimate bilinear / gradient interpolation residual on Green channel:
        # e(x,y) = G(x,y) - (G(x-1,y) + G(x+1,y) + G(x,y-1) + G(x,y+1)) / 4
        g_pad = np.pad(G, ((1, 1), (1, 1)), mode="reflect")
        neighbors = (
            g_pad[:-2, 1:-1] + g_pad[2:, 1:-1] + g_pad[1:-1, :-2] + g_pad[1:-1, 2:]
        ) * 0.25
        g_residual = G - neighbors

        # Compute 2D Fourier Spectrum of residual
        fft2 = np.fft.fft2(g_residual)
        fft_shift = np.fft.fftshift(np.abs(fft2))

        # In Bayer demosaicing, peak energy spikes appear at (0, pi), (pi, 0), and (pi, pi)
        # in the normalized frequency spectrum
        cy, cx = fft_shift.shape[0] // 2, fft_shift.shape[1] // 2
        nyquist_y = 0  # relative to center
        nyquist_x = 0

        # Sample high-frequency quadrant energy vs background noise floor
        total_energy = np.sum(fft_shift) + 1e-6
        center_mask = np.zeros_like(fft_shift, dtype=bool)
        center_mask[cy - 10 : cy + 10, cx - 10 : cx + 10] = True

        hf_corners = np.sum(fft_shift[0:15, 0:15]) + np.sum(fft_shift[-15:, -15:])
        hf_corners += np.sum(fft_shift[0:15, -15:]) + np.sum(fft_shift[-15:, 0:15])

        # Ratio of high-frequency periodic grid energy to total residual
        periodicity_ratio = float(hf_corners / total_energy) * 100.0
        # Normalize score between 0.0 and 1.0
        periodicity_score = round(min(1.0, periodicity_ratio / 5.0), 3)

        # Cross-channel correlation (R vs G and B vs G residuals)
        r_pad = np.pad(R, ((1, 1), (1, 1)), mode="reflect")
        r_neighbors = (r_pad[:-2, 1:-1] + r_pad[2:, 1:-1] + r_pad[1:-1, :-2] + r_pad[1:-1, 2:]) * 0.25
        r_residual = R - r_neighbors

        rg_corr = float(np.corrcoef(g_residual.flatten(), r_residual.flatten())[0, 1])
        if np.isnan(rg_corr):
            rg_corr = 0.0

        # Physical cameras typically exhibit high periodicity (> 0.25) and strong R-G residual correlation
        is_hardware_consistent = periodicity_score >= 0.20 and abs(rg_corr) > 0.15

        pattern = "RGGB_BAYER" if is_hardware_consistent else "NON_BAYER_OR_SYNTHETIC"

        return {
            "bayer_periodicity_score": periodicity_score,
            "channel_residual_correlation": round(rg_corr, 3),
            "cfa_pattern_detected": pattern,
            "is_hardware_sensor_consistent": is_hardware_consistent,
            "synthetic_raster_marker": not is_hardware_consistent,
        }
