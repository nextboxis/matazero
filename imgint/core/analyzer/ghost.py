"""JPEG Ghost and Double Compression Splicing Analyzer."""

from __future__ import annotations
import io
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from PIL import Image


class JpegGhostDetector:
    """Detects spliced regions and double JPEG compression artifacts across quality factors."""

    @staticmethod
    def analyze(
        img_or_bytes: Image.Image | bytes | np.ndarray,
        qualities: Optional[List[int]] = None,
        block_size: int = 16,
    ) -> Dict[str, Any]:
        if qualities is None:
            qualities = [50, 60, 70, 75, 80, 85, 90, 95]

        if isinstance(img_or_bytes, bytes):
            img = Image.open(io.BytesIO(img_or_bytes)).convert("RGB")
        elif isinstance(img_or_bytes, np.ndarray):
            img = Image.fromarray(img_or_bytes.astype(np.uint8)).convert("RGB")
        else:
            img = img_or_bytes.convert("RGB")

        # Resize if extremely large to prevent OOM
        max_dim = 1024
        w, h = img.size
        if max(w, h) > max_dim:
            scale = max_dim / float(max(w, h))
            img = img.resize((int(w * scale), int(h * scale)), Image.Resampling.BILINEAR)

        orig_np = np.array(img, dtype=np.float32)
        height, width, _ = orig_np.shape

        # Calculate error surface across quality factors
        error_surfaces: Dict[int, float] = {}

        for q in qualities:
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=q)
            buf.seek(0)
            recompressed = np.array(Image.open(buf), dtype=np.float32)

            # Mean absolute error
            diff = np.abs(orig_np - recompressed)
            mean_err = float(np.mean(diff))
            error_surfaces[q] = mean_err

        # Detect local minimums in the error curve (JPEG Ghost signature)
        err_keys = list(error_surfaces.keys())
        err_vals = list(error_surfaces.values())
        local_mins = []

        for i in range(1, len(err_keys) - 1):
            if err_vals[i] < err_vals[i - 1] and err_vals[i] <= err_vals[i + 1]:
                local_mins.append(err_keys[i])

        # Estimated primary quality is the lowest local minimum if present, else absolute min
        if local_mins:
            min_error_q = local_mins[0]
            is_double_compressed = True
        else:
            min_error_q = min(error_surfaces, key=error_surfaces.get)
            is_double_compressed = False

        # Compute 8x8 DCT grid boundary energy
        gray = np.mean(orig_np, axis=2)
        h_diff = np.abs(gray[1:, :] - gray[:-1, :])

        h_8_energy = np.mean(h_diff[7::8, :]) if h_diff.shape[0] > 8 else 0.0
        h_other_energy = np.mean(h_diff) + 1e-6
        grid_contrast = float(h_8_energy / h_other_energy)

        # Patch-wise local minimum variance for composite splicing detection
        step = block_size
        patch_best_q = []
        for y in range(0, height - step, step):
            for x in range(0, width - step, step):
                patch_orig = orig_np[y : y + step, x : x + step]
                p_min_q = 95
                p_min_val = float("inf")
                for q in qualities:
                    buf = io.BytesIO()
                    patch_img = Image.fromarray(patch_orig.astype(np.uint8))
                    patch_img.save(buf, format="JPEG", quality=q)
                    buf.seek(0)
                    patch_recomp = np.array(Image.open(buf), dtype=np.float32)
                    p_err = np.mean(np.abs(patch_orig - patch_recomp))
                    if p_err < p_min_val:
                        p_min_val = p_err
                        p_min_q = q
                patch_best_q.append(p_min_q)

        q_variance = float(np.var(patch_best_q)) if patch_best_q else 0.0
        is_spliced = q_variance > 180.0  # Multi-modal quality distribution indicates composite image

        return {
            "is_double_compressed": is_double_compressed,
            "estimated_primary_quality": min_error_q,
            "detected_ghost_minimums": local_mins,
            "quality_error_surface": {k: round(v, 4) for k, v in error_surfaces.items()},
            "quality_variance": round(q_variance, 2),
            "spliced_ghost_detected": is_spliced,
            "dct_8x8_grid_contrast": round(grid_contrast, 3),
            "grid_aligned": grid_contrast > 1.05,
        }
