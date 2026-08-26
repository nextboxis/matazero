"""Sandboxed child worker process executing decode-requiring analysers per ADR-004."""

from __future__ import annotations
import json
import sys
import os
import io
from pathlib import Path
from typing import Any, Dict


def process_decode_tasks(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """Decodes pixel data inside isolated child process and computes visual signals."""
    results: Dict[str, Any] = {"success": True, "tasks": {}}
    file_path = input_data.get("file_path")
    raw_bytes = input_data.get("raw_bytes")
    tasks = input_data.get("tasks", ["dimensions", "phashes", "dominant_colors", "entropy"])

    try:
        from PIL import Image, ImageStat
        import imagehash
        import numpy as np

        if file_path and os.path.exists(file_path):
            img = Image.open(file_path)
        elif raw_bytes:
            import base64
            img = Image.open(io.BytesIO(base64.b64decode(raw_bytes)))
        else:
            return {"success": False, "error": "No file path or raw bytes provided"}

        img_rgb = img.convert("RGB")
        width, height = img.size

        if "dimensions" in tasks:
            results["tasks"]["dimensions"] = {
                "width": width,
                "height": height,
                "aspect_ratio": round(width / max(1, height), 3),
                "mode": img.mode,
            }

        if "phashes" in tasks:
            ahash = str(imagehash.average_hash(img))
            dhash = str(imagehash.dhash(img))
            phash = str(imagehash.phash(img))
            results["tasks"]["phashes"] = {
                "ahash": ahash,
                "dhash": dhash,
                "phash": phash,
            }

        if "dominant_colors" in tasks:
            # Downsample for dominant color calculation
            small = img_rgb.resize((64, 64))
            stat = ImageStat.Stat(small)
            mean_rgb = [int(x) for x in stat.mean[:3]]
            hex_color = f"#{mean_rgb[0]:02X}{mean_rgb[1]:02X}{mean_rgb[2]:02X}"
            results["tasks"]["dominant_colors"] = {
                "mean_rgb": mean_rgb,
                "dominant_hex": hex_color,
            }

        if "entropy" in tasks:
            arr = np.array(img_rgb)
            # LSB entropy estimation
            lsb_arr = arr & 1
            lsb_mean = float(np.mean(lsb_arr))
            results["tasks"]["entropy"] = {
                "lsb_bit_density": round(lsb_mean, 4),
                "lsb_anomaly": bool(abs(lsb_mean - 0.5) > 0.15),
            }

        if "ela" in tasks:
            # Error Level Analysis simulation (re-compress at 90 and calculate diff)
            buffer = io.BytesIO()
            img_rgb.save(buffer, "JPEG", quality=90)
            buffer.seek(0)
            recompressed = Image.open(buffer).convert("RGB")
            diff = np.abs(np.array(img_rgb, dtype=np.int16) - np.array(recompressed, dtype=np.int16))
            max_diff = int(np.max(diff))
            avg_diff = float(np.mean(diff))
            results["tasks"]["ela"] = {
                "max_divergence": max_diff,
                "average_divergence": round(avg_diff, 2),
            }

    except Exception as e:
        return {"success": False, "error": str(e)}

    return results


def main() -> None:
    try:
        raw_in = sys.stdin.read()
        if not raw_in:
            print(json.dumps({"success": False, "error": "Empty stdin"}))
            return
        input_data = json.loads(raw_in)
        output = process_decode_tasks(input_data)
        print(json.dumps(output))
    except Exception as e:
        print(json.dumps({"success": False, "error": str(e)}))


if __name__ == "__main__":
    main()
