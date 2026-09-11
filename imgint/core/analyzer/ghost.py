"""JPEG Ghost and Double Compression Splicing Analyzer."""

from __future__ import annotations
import io
from typing import Any, Dict, List, Optional
import numpy as np
from PIL import Image
DEFAULT_GHOST_QUALITIES = [50, 60, 70, 75, 80, 85, 90, 95]
DEFAULT_MAX_ANALYSIS_DIM = 1024
SPLICING_VARIANCE_THRESHOLD = 180.0
GRID_CONTRAST_THRESHOLD = 1.05


class JpegGhostDetector:
    """Detects spliced regions and double JPEG compression artifacts across quality factors."""

    @staticmethod
    def analyze(
        img_or_bytes: Image.Image | bytes | np.ndarray,
        qualities: Optional[List[int]] = None,
        block_size: int = 16,
    ) -> Dict[str, Any]:
        _empty_result = {
            "is_double_compressed": False,
            "estimated_primary_quality": None,
            "detected_ghost_minimums": [],
            "quality_error_surface": {},
            "quality_variance": 0.0,
            "spliced_ghost_detected": False,
            "dct_8x8_grid_contrast": 0.0,
            "grid_aligned": False,
        }

        if qualities is None:
            qualities = DEFAULT_GHOST_QUALITIES

        try:
            if isinstance(img_or_bytes, bytes):
                img = Image.open(io.BytesIO(img_or_bytes)).convert("RGB")
            elif isinstance(img_or_bytes, np.ndarray):
                img = Image.fromarray(img_or_bytes.astype(np.uint8)).convert("RGB")
            else:
                img = img_or_bytes.convert("RGB")
        except (OSError, ValueError, SyntaxError):
            return _empty_result

        max_dim = DEFAULT_MAX_ANALYSIS_DIM
        w, h = img.size
        if w == 0 or h == 0:
            return _empty_result
        if max(w, h) > max_dim:
            scale = max_dim / float(max(w, h))
            new_w, new_h = max(1, int(w * scale)), max(1, int(h * scale))
            img = img.resize((new_w, new_h), Image.Resampling.BILINEAR)

        orig_np = np.array(img, dtype=np.float32)
        height, width, _ = orig_np.shape

        error_surfaces: Dict[int, float] = {}
        pre_computed_errors: Dict[int, np.ndarray] = {}

        for q in qualities:
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=q)
            buf.seek(0)
            recompressed = np.array(Image.open(buf), dtype=np.float32)

            diff = np.abs(orig_np - recompressed)
            pre_computed_errors[q] = diff
            mean_err = float(np.mean(diff))
            error_surfaces[q] = mean_err

        err_keys = list(error_surfaces.keys())
        err_vals = list(error_surfaces.values())
        local_mins = []

        for i in range(1, len(err_keys) - 1):
            if err_vals[i] < err_vals[i - 1] and err_vals[i] <= err_vals[i + 1]:
                local_mins.append(err_keys[i])

        if local_mins:
            min_error_q = local_mins[0]
            is_double_compressed = True
        else:
            min_error_q = min(error_surfaces, key=error_surfaces.get)
            is_double_compressed = False

        gray = np.mean(orig_np, axis=2)
        h_diff = np.abs(gray[1:, :] - gray[:-1, :])

        h_8_energy = np.mean(h_diff[7::8, :]) if h_diff.shape[0] >= 8 else 0.0
        h_other_energy = np.mean(h_diff) + 1e-6

        if np.isnan(h_other_energy) or np.isnan(h_8_energy) or h_other_energy == 0:
            grid_contrast = 0.0
        else:
            grid_contrast = float(h_8_energy / h_other_energy)

        step = block_size
        patch_best_q = []
        for y in range(0, height - step + 1, step):
            for x in range(0, width - step + 1, step):
                patch_errors = {}
                for q in qualities:
                    patch_errors[q] = float(np.mean(pre_computed_errors[q][y : y + step, x : x + step]))
                best_q = min(patch_errors, key=patch_errors.get)
                patch_best_q.append(best_q)

        q_variance = float(np.var(patch_best_q)) if patch_best_q else 0.0
        is_spliced = q_variance > SPLICING_VARIANCE_THRESHOLD

        return {
            "is_double_compressed": is_double_compressed,
            "estimated_primary_quality": min_error_q,
            "detected_ghost_minimums": local_mins,
            "quality_error_surface": {k: round(v, 4) for k, v in error_surfaces.items()},
            "quality_variance": round(q_variance, 2),
            "spliced_ghost_detected": is_spliced,
            "dct_8x8_grid_contrast": round(grid_contrast, 3),
            "grid_aligned": grid_contrast > GRID_CONTRAST_THRESHOLD,
        }
