"""CLI integration tests for probe, extract, and analyze with value locations."""

import subprocess
import sys
import tempfile
from pathlib import Path
from fractions import Fraction
from PIL import Image
import io
import sys

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def create_test_image() -> Path:
    img = Image.new("RGB", (200, 200), color=(100, 180, 220))
    exif = img.getexif()
    exif[0x010F] = "Nikon"
    exif[0x0110] = "D850"
    exif[0x0132] = "2026:08:26 14:30:00"

    gps_ifd = exif.get_ifd(0x8825)
    gps_ifd[0x0001] = "N"
    gps_ifd[0x0002] = (Fraction(40, 1), Fraction(42, 1), Fraction(46, 1))
    gps_ifd[0x0003] = "W"
    gps_ifd[0x0004] = (Fraction(74, 1), Fraction(0, 1), Fraction(21, 1))
    gps_ifd[0x0006] = Fraction(15, 1)
    gps_ifd[0x001D] = "2026:08:26"

    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif)
    jpeg_bytes = buf.getvalue()

    fake_payload = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"EMBEDDED_ZIP_PAYLOAD"
    full_data = jpeg_bytes + fake_payload

    tmp = tempfile.NamedTemporaryFile(suffix=".jpg", delete=False)
    tmp.write(full_data)
    tmp.close()
    return Path(tmp.name)


def run_cli_tests():
    p = create_test_image()
    try:
        # Test 1: Probe command
        print("Testing: matazero probe")
        res = subprocess.run(
            [sys.executable, "-m", "matazero", "probe", str(p)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        print("PROBE STDOUT:")
        print(res.stdout)
        if res.stderr:
            print("PROBE STDERR:")
            print(res.stderr)
        assert res.returncode == 0, f"Probe failed: {res.stderr}"
        assert "Metadata Fields & Value Locations" in res.stdout
        assert "Tag Offset" in res.stdout or "Offset" in res.stdout
        print(" -> Probe output verified successfully")

        # Test 2: Extract command (All artefacts)
        print("Testing: matazero extract --all")
        with tempfile.TemporaryDirectory() as out_d:
            res = subprocess.run(
                [sys.executable, "-m", "matazero", "extract", str(p), "-o", out_d, "-a"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            assert res.returncode == 0, f"Extract failed: {res.stderr}"
            assert "Successfully extracted" in res.stdout
            out_files = list(Path(out_d).glob("*"))
            assert len(out_files) > 0, "No files extracted"
            print(f" -> Extract all created {len(out_files)} files: {[f.name for f in out_files]}")

        # Test 3: Extract with -x, -y crop coordinates
        print("Testing: matazero extract -x -y")
        with tempfile.TemporaryDirectory() as out_d:
            res = subprocess.run(
                [sys.executable, "-m", "matazero", "extract", str(p), "-x", "50", "-y", "60", "-w", "80", "-h", "80", "-o", out_d],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            assert res.returncode == 0, f"Extract -x -y failed: {res.stderr}"
            assert "crop" in res.stdout.lower()
            crops = list(Path(out_d).glob("*crop*"))
            assert len(crops) > 0, "Crop file was not created"
            print(f" -> Extract -x -y crop created: {crops[0].name}")

        # Test 4: Analyze command self-audit
        print("Testing: matazero analyze -a")
        res = subprocess.run(
            [sys.executable, "-m", "matazero", "analyze", str(p), "-a"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert res.returncode == 0, f"Analyze failed: {res.stderr}"
        assert "X / Y Location" in res.stdout or "Coordinates" in res.stdout
        assert "Value Offsets" in res.stdout or "Val @" in res.stdout
        print(" -> Analyze report verified successfully")

    finally:
        if p.exists():
            p.unlink()

    print("ALL CLI INTEGRATION TESTS PASSED!")


if __name__ == "__main__":
    run_cli_tests()
