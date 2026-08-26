"""CLI integration tests for matazero locate and complex analyze queries."""

import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from fractions import Fraction
from PIL import Image

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def create_gps_image(lat_deg: float, lon_deg: float, time_str: str = "2026:08:26 12:00:00") -> Path:
    img = Image.new("RGB", (100, 100), color=(100, 150, 200))
    exif = img.getexif()
    exif[0x010F] = "Sony"
    exif[0x0110] = "A7R V"
    exif[0x0132] = time_str

    lat_card = "N" if lat_deg >= 0 else "S"
    lon_card = "E" if lon_deg >= 0 else "W"
    abs_lat = abs(lat_deg)
    abs_lon = abs(lon_deg)

    lat_d = int(abs_lat)
    lat_m = int((abs_lat - lat_d) * 60)
    lat_s = ((abs_lat - lat_d) * 60 - lat_m) * 60

    lon_d = int(abs_lon)
    lon_m = int((abs_lon - lon_d) * 60)
    lon_s = ((abs_lon - lon_d) * 60 - lon_m) * 60

    gps_ifd = exif.get_ifd(0x8825)
    gps_ifd[0x0001] = lat_card
    gps_ifd[0x0002] = (Fraction(lat_d, 1), Fraction(lat_m, 1), Fraction(int(lat_s * 100), 100))
    gps_ifd[0x0003] = lon_card
    gps_ifd[0x0004] = (Fraction(lon_d, 1), Fraction(lon_m, 1), Fraction(int(lon_s * 100), 100))
    gps_ifd[0x0006] = Fraction(25, 1)
    gps_ifd[0x001D] = time_str.split()[0].replace(":", "-")

    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif)
    tmp = tempfile.NamedTemporaryFile(suffix=".jpg", delete=False)
    tmp.write(buf.getvalue())
    tmp.close()
    return Path(tmp.name)


def run_tests():
    # Image 1: London (51.5074, -0.1278) at 12:00:00
    p1 = create_gps_image(51.5074, -0.1278, "2026:08:26 12:00:00")
    # Image 2: Paris (48.8566, 2.3522) at 12:30:00 (~343 km away in 30 mins -> ~686 km/h)
    p2 = create_gps_image(48.8566, 2.3522, "2026:08:26 12:30:00")
    # Image 3: Tokyo (35.6762, 139.6503) at 12:35:00 (~9700 km in 5 mins -> supersonic travel anomaly!)
    p3 = create_gps_image(35.6762, 139.6503, "2026:08:26 12:35:00")

    try:
        # Test 1: Single Image locate (table format)
        print("Testing: matazero locate <single_image>")
        res = subprocess.run(
            [sys.executable, "-m", "matazero", "locate", str(p1), "-a"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert res.returncode == 0, f"Locate failed: {res.stderr}"
        assert "London" in res.stdout or "51.50" in res.stdout
        print(" -> Single image locate passed")

        # Test 2: Multi-Image locate with HTML dossier map export
        print("Testing: matazero locate multi-target with HTML map export")
        with tempfile.TemporaryDirectory() as out_d:
            html_out = Path(out_d) / "dossier.html"
            res = subprocess.run(
                [sys.executable, "-m", "matazero", "locate", str(p1), str(p2), str(p3), "-a", "-f", "html", "-o", str(html_out)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            assert res.returncode == 0, f"HTML map export failed: {res.stderr}"
            assert html_out.exists()
            content = html_out.read_text(encoding="utf-8")
            assert "Leaflet" in content or "L.map" in content
            assert "London" in content or "51.5074" in content
            print(f" -> Interactive Leaflet HTML Map generated ({html_out.stat().st_size:,} bytes)")

        # Test 3: GeoJSON and GPX export
        print("Testing: matazero locate GeoJSON and GPX exports")
        with tempfile.TemporaryDirectory() as out_d:
            geojson_out = Path(out_d) / "evidence.geojson"
            gpx_out = Path(out_d) / "track.gpx"

            res_geo = subprocess.run(
                [sys.executable, "-m", "matazero", "locate", str(p1), str(p2), "-a", "-f", "geojson", "-o", str(geojson_out)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            assert res_geo.returncode == 0
            assert geojson_out.exists()
            geo_data = json.loads(geojson_out.read_text(encoding="utf-8"))
            assert geo_data["type"] == "FeatureCollection"

            res_gpx = subprocess.run(
                [sys.executable, "-m", "matazero", "locate", str(p1), str(p2), "-a", "-f", "gpx", "-o", str(gpx_out)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            assert res_gpx.returncode == 0
            assert gpx_out.exists()
            assert "<trkpt" in gpx_out.read_text(encoding="utf-8")
            print(" -> GeoJSON and GPX exports verified")

        # Test 4: Multi-target trajectory report & travel speed anomaly detection
        print("Testing: multi-target trajectory & speed anomaly detection")
        res_rep = subprocess.run(
            [sys.executable, "-m", "matazero", "locate", str(p1), str(p2), str(p3), "-a", "-f", "report"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        print("REPORT STDOUT:")
        print(res_rep.stdout)
        if res_rep.stderr:
            print("REPORT STDERR:", res_rep.stderr)
        assert res_rep.returncode == 0
        assert "TRAJECTORY ANALYSIS" in res_rep.stdout
        assert "VELOCITY & TRAVEL IMPOSSIBILITY ANOMALIES" in res_rep.stdout
        print(" -> Velocity anomaly correctly triggered and reported")

        # Test 5: Complex analyze query with directory, --filter, --select-fields, -j 2
        print("Testing: matazero analyze with --filter, --select-fields, -j 2")
        with tempfile.TemporaryDirectory() as folder_dir:
            # Copy images to folder
            (Path(folder_dir) / "img1.jpg").write_bytes(p1.read_bytes())
            (Path(folder_dir) / "img2.jpg").write_bytes(p2.read_bytes())

            res_analyze = subprocess.run(
                [
                    sys.executable, "-m", "matazero", "analyze", folder_dir,
                    "-a", "-r", "--filter", "has_gps", "--select-fields", "Make,Model,GPSLatitude",
                    "-j", "2", "-f", "table"
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            assert res_analyze.returncode == 0, f"Analyze batch failed: {res_analyze.stderr}"
            assert "Analysis Summary (2 Files)" in res_analyze.stdout
            print(" -> Complex batch analysis with concurrency and filtering passed")

    finally:
        for p in (p1, p2, p3):
            if p.exists():
                p.unlink()

    print("ALL CLI LOCATE & COMPLEX ANALYZE INTEGRATION TESTS PASSED!")


if __name__ == "__main__":
    run_tests()
