"""Copy-Move and Clone-Stamp Forgery Detector."""

from __future__ import annotations
import io
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from PIL import Image


class CopyMoveDetector:
    """Detects duplicated or clone-stamped regions using block-based feature matching and shift vectors."""

    @staticmethod
    def analyze(
        img_or_bytes: Image.Image | bytes | np.ndarray,
        block_size: int = 16,
        step_size: int = 8,
        min_distance: int = 32,
        similarity_threshold: float = 0.96,
    ) -> Dict[str, Any]:
        if isinstance(img_or_bytes, bytes):
            img = Image.open(io.BytesIO(img_or_bytes)).convert("L")
        elif isinstance(img_or_bytes, np.ndarray):
            if len(img_or_bytes.shape) == 3:
                img = Image.fromarray(img_or_bytes.astype(np.uint8)).convert("L")
            else:
                img = Image.fromarray(img_or_bytes.astype(np.uint8))
        else:
            img = img_or_bytes.convert("L")

        # Resize for performance if large
        max_dim = 512
        w, h = img.size
        scale = 1.0
        if max(w, h) > max_dim:
            scale = max_dim / float(max(w, h))
            img = img.resize((int(w * scale), int(h * scale)), Image.Resampling.BILINEAR)

        arr = np.array(img, dtype=np.float32)
        height, width = arr.shape

        if height < block_size * 2 or width < block_size * 2:
            return {
                "copy_move_detected": False,
                "cloned_cluster_count": 0,
                "shift_vectors": [],
                "cloned_regions": [],
            }

        # Extract blocks and their feature representations (mean, std, 4-quadrant means)
        blocks = []
        positions = []

        for y in range(0, height - block_size + 1, step_size):
            for x in range(0, width - block_size + 1, step_size):
                patch = arr[y : y + block_size, x : x + block_size]
                # Skip flat/low-entropy background (e.g. solid white/black/sky)
                std_val = float(np.std(patch))
                if std_val < 8.0:
                    continue

                # 6-dimensional feature vector: mean, std, 4 quadrant means
                half = block_size // 2
                q1 = np.mean(patch[:half, :half])
                q2 = np.mean(patch[:half, half:])
                q3 = np.mean(patch[half:, :half])
                q4 = np.mean(patch[half:, half:])
                mean_val = np.mean(patch)

                feat = np.array([mean_val, std_val, q1, q2, q3, q4], dtype=np.float32)
                blocks.append(feat)
                positions.append((x, y))

        if len(blocks) < 10:
            return {
                "copy_move_detected": False,
                "cloned_cluster_count": 0,
                "shift_vectors": [],
                "cloned_regions": [],
            }

        blocks_arr = np.array(blocks)
        num_blocks = len(blocks_arr)

        # Lexicographical sort on primary features for fast neighbor matching
        sort_idx = np.lexsort((blocks_arr[:, 1], blocks_arr[:, 0]))
        sorted_blocks = blocks_arr[sort_idx]
        sorted_pos = [positions[i] for i in sort_idx]

        # Find matching pairs within a local search window
        shift_vector_counts: Dict[Tuple[int, int], int] = {}
        matched_regions: List[Dict[str, Any]] = []

        search_window = min(30, num_blocks)
        for i in range(num_blocks - 1):
            f1 = sorted_blocks[i]
            p1 = sorted_pos[i]
            for j in range(i + 1, min(i + search_window, num_blocks)):
                f2 = sorted_blocks[j]
                p2 = sorted_pos[j]

                # Spatial Euclidean distance
                dx = p2[0] - p1[0]
                dy = p2[1] - p1[1]
                dist = np.sqrt(dx * dx + dy * dy)
                if dist < min_distance:
                    continue

                # Feature similarity check (normalized difference)
                diff = np.abs(f1 - f2) / (np.abs(f1) + np.abs(f2) + 1e-6)
                if np.max(diff) < (1.0 - similarity_threshold):
                    # Quantize shift vector to 16px bins
                    if dx < 0 or (dx == 0 and dy < 0):
                        dx, dy = -dx, -dy
                    shift_key = (round(dx / 16) * 16, round(dy / 16) * 16)
                    shift_vector_counts[shift_key] = shift_vector_counts.get(shift_key, 0) + 1

                    if len(matched_regions) < 10:
                        matched_regions.append({
                            "source": {"x": int(p1[0] / scale), "y": int(p1[1] / scale)},
                            "target": {"x": int(p2[0] / scale), "y": int(p2[1] / scale)},
                            "block_size": int(block_size / scale),
                        })

        # A significant cluster of identical shift vectors indicates deliberate clone-stamping
        significant_clusters = [k for k, count in shift_vector_counts.items() if count >= 4]
        is_cloned = len(significant_clusters) > 0

        return {
            "copy_move_detected": is_cloned,
            "cloned_cluster_count": len(significant_clusters),
            "dominant_shift_vectors": [{"dx": k[0], "dy": k[1], "count": shift_vector_counts[k]} for k in significant_clusters],
            "cloned_regions": matched_regions if is_cloned else [],
            "confidence": 0.85 if is_cloned else 0.1,
        }
