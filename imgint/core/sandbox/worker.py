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

        if "fft_frequency" in tasks:
            # 2D Fast Fourier Transform Power Spectrum for Synthetic / GenAI Artifact Detection
            arr = np.array(img_rgb)
            gray = np.dot(arr[..., :3], [0.2989, 0.5870, 0.1140])
            h_crop = min(512, height)
            w_crop = min(512, width)
            sub_gray = gray[:h_crop, :w_crop]
            f_shift = np.fft.fftshift(np.fft.fft2(sub_gray))
            mag = np.abs(f_shift)
            cy, cx = h_crop // 2, w_crop // 2
            r_core = min(cy, cx) // 4
            # Mask low frequencies in center to analyze high-frequency grid peaks
            y_coords, x_coords = np.ogrid[:h_crop, :w_crop]
            dist_from_center = np.sqrt((x_coords - cx) ** 2 + (y_coords - cy) ** 2)
            high_freq_mask = dist_from_center > r_core
            high_freq_mag = mag[high_freq_mask]
            
            p99 = float(np.percentile(high_freq_mag, 99.5)) if len(high_freq_mag) > 0 else 0.0
            mean_hf = float(np.mean(high_freq_mag)) if len(high_freq_mag) > 0 else 1.0
            peak_ratio = round(p99 / max(1e-5, mean_hf), 2)
            
            results["tasks"]["fft_frequency"] = {
                "fft_peak_ratio": peak_ratio,
                "high_frequency_mean": round(mean_hf, 2),
                "synthetic_grid_artifact": bool(peak_ratio > 18.0),
                "description": "2D Fourier power spectrum analysis for periodic upsampling grid spikes",
            }

        if "chi_square" in tasks:
            # Chi-Square (PoV) Steganography Analysis on LSBs
            arr = np.array(img_rgb)
            chi_stats = {}
            for c_idx, c_name in enumerate(["red", "green", "blue"]):
                channel = arr[..., c_idx].flatten()
                hist = np.bincount(channel, minlength=256)
                chi_sum = 0.0
                dof = 0
                for k in range(128):
                    observed = hist[2 * k]
                    total_pair = hist[2 * k] + hist[2 * k + 1]
                    expected = total_pair / 2.0
                    if expected > 5:
                        chi_sum += ((observed - expected) ** 2) / expected
                        dof += 1
                chi_stats[c_name] = {
                    "chi_square_stat": round(float(chi_sum), 2),
                    "degrees_of_freedom": dof,
                    "uniform_lsb_pairing_suspected": bool(dof > 30 and chi_sum < (dof * 0.4)),
                }
            results["tasks"]["chi_square"] = chi_stats

        if "bitplane_slice" in tasks:
            # Bitplane slicing entropy for planes 0 (LSB) through 7 (MSB)
            arr = np.array(img_rgb)
            bitplane_data = {}
            for c_idx, c_name in enumerate(["red", "green", "blue"]):
                c_planes = {}
                for p in range(8):
                    bits = (arr[..., c_idx] >> p) & 1
                    mean_b = float(np.mean(bits))
                    if 0 < mean_b < 1:
                        ent = float(-mean_b * np.log2(mean_b) - (1 - mean_b) * np.log2(1 - mean_b))
                    else:
                        ent = 0.0
                    c_planes[f"plane_{p}"] = {
                        "bit_density": round(mean_b, 4),
                        "entropy": round(ent, 4),
                    }
                bitplane_data[c_name] = c_planes
            results["tasks"]["bitplane_slice"] = bitplane_data

        if "pixel_diff" in tasks:
            compare_path = input_data.get("compare_file_path")
            if compare_path and os.path.exists(compare_path):
                img2 = Image.open(compare_path).convert("RGB")
                if img2.size != (width, height):
                    img2 = img2.resize((width, height))
                arr1 = np.array(img_rgb, dtype=np.int16)
                arr2 = np.array(img2, dtype=np.int16)
                diff = np.abs(arr1 - arr2)
                altered_pixels = int(np.sum(np.any(diff > 0, axis=-1)))
                total_pixels = width * height
                altered_pct = round((altered_pixels / max(1, total_pixels)) * 100.0, 2)
                mse = float(np.mean(diff.astype(np.float64) ** 2))
                max_d = int(np.max(diff))
                results["tasks"]["pixel_diff"] = {
                    "identical_pixels": bool(altered_pixels == 0),
                    "altered_pixels_count": altered_pixels,
                    "altered_pixels_pct": altered_pct,
                    "mean_squared_error": round(mse, 4),
                    "max_channel_diff": max_d,
                    "estimated_ssim": round(max(0.0, 1.0 - (mse / (255.0 ** 2))), 4),
                }

        if "ghost" in tasks:
            from imgint.core.analyzer.ghost import JpegGhostDetector
            results["tasks"]["ghost"] = JpegGhostDetector.analyze(img_rgb)

        if "cfa" in tasks:
            from imgint.core.analyzer.cfa import CfaDemosaicAnalyzer
            results["tasks"]["cfa"] = CfaDemosaicAnalyzer.analyze(img_rgb)

        if "copymove" in tasks:
            from imgint.core.analyzer.copymove import CopyMoveDetector
            results["tasks"]["copymove"] = CopyMoveDetector.analyze(img_rgb)

        if "crop" in tasks:
            x = int(input_data.get("x", 0))
            y = int(input_data.get("y", 0))
            w = int(input_data.get("width", 100))
            h = int(input_data.get("height", 100))
            crop_out = input_data.get("crop_out_path")

            box_x1 = max(0, min(width - 1, x))
            box_y1 = max(0, min(height - 1, y))
            box_x2 = max(box_x1 + 1, min(width, x + w))
            box_y2 = max(box_y1 + 1, min(height, y + h))

            cropped_img = img_rgb.crop((box_x1, box_y1, box_x2, box_y2))
            if crop_out:
                Path(crop_out).parent.mkdir(parents=True, exist_ok=True)
                cropped_img.save(crop_out)

            results["tasks"]["crop"] = {
                "x": x,
                "y": y,
                "width": box_x2 - box_x1,
                "height": box_y2 - box_y1,
                "box": [box_x1, box_y1, box_x2, box_y2],
                "output_path": crop_out,
            }

        if "pixel_at_xy" in tasks:
            px = int(input_data.get("x", 0))
            py = int(input_data.get("y", 0))
            if 0 <= px < width and 0 <= py < height:
                pix = img_rgb.getpixel((px, py))
                r, g, b = pix[:3]
                results["tasks"]["pixel_at_xy"] = {
                    "x": px,
                    "y": py,
                    "rgb": [r, g, b],
                    "hex": f"#{r:02X}{g:02X}{b:02X}",
                }
            else:
                results["tasks"]["pixel_at_xy"] = {
                    "x": px,
                    "y": py,
                    "error": f"Coordinates ({px}, {py}) out of bounds ({width}x{height})",
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
