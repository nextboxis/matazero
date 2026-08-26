"""Tier 5 Geospatial and Temporal Consistency Analyzer per SRD FR-6.1 - FR-6.8 and GR-4.4."""

from __future__ import annotations
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from imgint.core.analyzer.base import Analyzer, AnalysisContext
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import Diagnostic


class GeoTimeAnalyzer(Analyzer):
    """Parses GPS coordinates, performs offline reverse geocoding, solar chronolocation, and temporal consistency cross-checks."""

    @property
    def id(self) -> str:
        return "tier5_geotime"

    @property
    def tier(self) -> int:
        return 5

    @property
    def requires_decode(self) -> bool:
        return False

    def analyze(self, ctx: AnalysisContext) -> Tuple[List[Finding], List[Diagnostic]]:
        findings: List[Finding] = []
        diagnostics: List[Diagnostic] = []

        lat_raw = ctx.get_field_value("GPSLatitude")
        lat_ref = ctx.get_field_value("GPSLatitudeRef") or "N"
        lon_raw = ctx.get_field_value("GPSLongitude")
        lon_ref = ctx.get_field_value("GPSLongitudeRef") or "E"
        alt_raw = ctx.get_field_value("GPSAltitude")
        alt_ref = ctx.get_field_value("GPSAltitudeRef")
        dop_raw = ctx.get_field_value("GPSDOP")
        gps_date = ctx.get_field_value("GPSDateStamp")
        gps_time = ctx.get_field_value("GPSTimeStamp")
        date_orig = ctx.get_field_value("DateTimeOriginal") or ctx.get_field_value("DateTime")
        offset_time = ctx.get_field_value("OffsetTimeOriginal") or ctx.get_field_value("OffsetTime")

        lat_dec: Optional[float] = None
        lon_dec: Optional[float] = None

        # FR-6.1: Convert GPS rational triplets to signed decimal degrees
        if lat_raw and lon_raw:
            try:
                lat_dec = self._convert_dms_to_decimal(lat_raw, lat_ref)
                lon_dec = self._convert_dms_to_decimal(lon_raw, lon_ref)
            except Exception as e:
                diagnostics.append(Diagnostic(level="warning", message=f"GPS coordinate conversion failed: {e}", source="geotime_analyzer"))

        if lat_dec is not None and lon_dec is not None:
            findings.append(
                Finding(
                    name="gps_coordinates_claimed",
                    value={
                        "latitude": round(lat_dec, 6),
                        "longitude": round(lon_dec, 6),
                        "latitude_ref": lat_ref,
                        "longitude_ref": lon_ref,
                    },
                    tier=5,
                    extractor="geotime_analyzer",
                    confidence=Confidence.DERIVED,
                    caveat=(
                        "GPS coordinates reflect data recorded in image metadata by the device. "
                        "They can be manually edited, injected, or altered by third-party tools (FR-6.8)."
                    ),
                    provenance=Provenance(source_layer="analyzer", extractor="geotime_analyzer", standard="EXIF"),
                )
            )

            # FR-6.3 & GR-4.4: Offline reverse geocoding
            offline_place = self._offline_reverse_geocode(lat_dec, lon_dec)
            if offline_place:
                findings.append(
                    Finding(
                        name="offline_reverse_geocode",
                        value=offline_place,
                        tier=5,
                        extractor="offline_geocoder",
                        confidence=Confidence.DERIVED,
                        caveat=(
                            "Reverse geocoding performed using bundled offline GeoNames index (GR-4.4). "
                            "Represents closest administrative center."
                        ),
                        provenance=Provenance(source_layer="analyzer", extractor="offline_geocoder"),
                    )
                )

        # GPS Altitude & DOP (FR-6.2)
        if alt_raw:
            alt_m = self._convert_rational_to_float(alt_raw)
            if alt_ref in (1, "1"):
                alt_m = -alt_m
            findings.append(
                Finding(
                    name="gps_altitude_claimed",
                    value={"altitude_meters": round(alt_m, 2)},
                    tier=5,
                    extractor="geotime_analyzer",
                    confidence=Confidence.DERIVED,
                    caveat="Altitude claim from device barometric/GPS sensor; precision varies widely.",
                    provenance=Provenance(source_layer="analyzer", extractor="geotime_analyzer"),
                )
            )

        # FR-6.4: NOAA Solar position calculation for chronolocation
        dt_capture = self._parse_datetime(date_orig)
        if lat_dec is not None and lon_dec is not None and dt_capture is not None:
            solar_pos = self._compute_noaa_solar_position(lat_dec, lon_dec, dt_capture)
            if solar_pos:
                findings.append(
                    Finding(
                        name="solar_position_expected",
                        value=solar_pos,
                        tier=5,
                        extractor="solar_calculator",
                        confidence=Confidence.DERIVED,
                        caveat=(
                            "Expected solar azimuth and elevation computed using NOAA algorithm from claimed GPS and timestamp. "
                            "Provided for analyst comparison against visible shadow geometry."
                        ),
                        provenance=Provenance(source_layer="analyzer", extractor="solar_calculator"),
                    )
                )

        # FR-6.5: Cross-check DateTimeOriginal vs GPSDateStamp
        if date_orig and gps_date:
            date_orig_prefix = str(date_orig).replace(":", "-")[:10]
            gps_date_clean = str(gps_date).replace(":", "-")[:10]
            if date_orig_prefix != gps_date_clean:
                findings.append(
                    Finding(
                        name="temporal_crosscheck_divergence",
                        value={
                            "datetime_original_date": date_orig_prefix,
                            "gps_datestamp_date": gps_date_clean,
                            "divergence": "Dates disagree",
                        },
                        tier=5,
                        extractor="temporal_crosscheck",
                        confidence=Confidence.INDICATIVE,
                        caveat="Discrepancy may result from camera clock drift, unsynchronized GPS lock, or manual metadata edit.",
                        provenance=Provenance(source_layer="analyzer", extractor="temporal_crosscheck"),
                    )
                )

        # FR-6.6: Timezone offset plausibility vs longitude
        if offset_time and lon_dec is not None:
            try:
                sign = -1 if offset_time.startswith("-") else 1
                parts = offset_time.lstrip("+-").split(":")
                hours = int(parts[0]) + (int(parts[1]) / 60.0 if len(parts) > 1 else 0)
                claimed_tz_offset = sign * hours
                expected_tz_approx = lon_dec / 15.0  # ~15 degrees per timezone hour

                diff = abs(claimed_tz_offset - expected_tz_approx)
                if diff > 3.0:  # More than 3 hours deviation from solar solar longitude timezone
                    findings.append(
                        Finding(
                            name="timezone_longitude_inconsistency",
                            value={
                                "claimed_offset_hours": claimed_tz_offset,
                                "expected_solar_offset_approx": round(expected_tz_approx, 1),
                                "discrepancy_hours": round(diff, 1),
                            },
                            tier=5,
                            extractor="temporal_crosscheck",
                            confidence=Confidence.INDICATIVE,
                            caveat="Significant divergence between longitude and recorded timezone offset. May indicate traveling across timezones or device misconfiguration.",
                            provenance=Provenance(source_layer="analyzer", extractor="temporal_crosscheck"),
                        )
                    )
            except Exception:
                pass

        # FR-6.7: Filesystem mtime vs claimed capture time
        try:
            mtime_epoch = ctx.file_path.stat().st_mtime
            if dt_capture:
                capture_epoch = dt_capture.timestamp()
                if mtime_epoch < capture_epoch - 60:  # mtime precedes capture time
                    findings.append(
                        Finding(
                            name="filesystem_mtime_precedes_capture",
                            value={
                                "filesystem_mtime_utc": datetime.fromtimestamp(mtime_epoch, timezone.utc).isoformat(),
                                "claimed_capture_time_utc": dt_capture.isoformat(),
                            },
                            tier=5,
                            extractor="temporal_crosscheck",
                            confidence=Confidence.INDICATIVE,
                            caveat="Filesystem modification time precedes claimed capture time. Common in timestomping, archive extraction, or camera clock errors.",
                            provenance=Provenance(source_layer="analyzer", extractor="temporal_crosscheck"),
                        )
                    )
        except Exception:
            pass

        return findings, diagnostics

    def _convert_dms_to_decimal(self, dms_raw: Any, ref: str) -> float:
        if isinstance(dms_raw, (int, float)):
            val = float(dms_raw)
            if ref in ("S", "W"):
                val = -val
            return val

        if isinstance(dms_raw, list) and len(dms_raw) >= 3:
            deg = self._convert_rational_to_float(dms_raw[0])
            mins = self._convert_rational_to_float(dms_raw[1])
            secs = self._convert_rational_to_float(dms_raw[2])
            dec = deg + (mins / 60.0) + (secs / 3600.0)
            if ref in ("S", "W"):
                dec = -dec
            return dec
        raise ValueError(f"Unrecognized DMS structure {dms_raw}")

    def _convert_rational_to_float(self, val: Any) -> float:
        if isinstance(val, list) and len(val) == 2:
            num, den = val
            return float(num) / float(den) if den != 0 else float(num)
        return float(val)

    def _offline_reverse_geocode(self, lat: float, lon: float) -> Optional[Dict[str, Any]]:
        geo_file = Path(__file__).parent.parent / "data" / "geonames_offline.json"
        if not geo_file.exists():
            return None
        try:
            with open(geo_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                places = data.get("places", [])
                if not places:
                    return None

                closest = None
                min_dist = float("inf")
                for p in places:
                    plat = p["lat"]
                    plon = p["lon"]
                    # Euclidean distance approximation for nearby points
                    d = math.hypot(lat - plat, (lon - plon) * math.cos(math.radians(lat)))
                    if d < min_dist:
                        min_dist = d
                        closest = p

                if closest:
                    dist_km = min_dist * 111.0
                    return {
                        "closest_city": closest["name"],
                        "admin_region": closest["admin1"],
                        "country": closest["country"],
                        "timezone": closest.get("timezone"),
                        "approx_distance_km": round(dist_km, 1),
                    }
        except Exception:
            pass
        return None

    def _parse_datetime(self, date_str: Optional[str]) -> Optional[datetime]:
        if not date_str or not isinstance(date_str, str):
            return None
        formats = [
            "%Y:%m:%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
        ]
        clean_str = date_str.strip().split("+")[0].split(".")[0]
        for fmt in formats:
            try:
                dt = datetime.strptime(clean_str, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass
        return None

    def _compute_noaa_solar_position(self, lat: float, lon: float, dt: datetime) -> Optional[Dict[str, Any]]:
        """Calculates expected solar elevation and azimuth using NOAA approximation."""
        try:
            # Day of year
            day_of_year = dt.timetuple().tm_yday
            hour_float = dt.hour + dt.minute / 60.0 + dt.second / 3600.0

            # Fractional year in radians
            gamma = 2.0 * math.pi / 365.0 * (day_of_year - 1 + (hour_float - 12.0) / 24.0)

            # Equation of time in minutes
            eqtime = 229.18 * (0.000075 + 0.001868 * math.cos(gamma) - 0.032077 * math.sin(gamma) - 0.014615 * math.cos(2 * gamma) - 0.040849 * math.sin(2 * gamma))

            # Solar declination angle in radians
            decl = 0.006918 - 0.399912 * math.cos(gamma) + 0.070257 * math.sin(gamma) - 0.006758 * math.cos(2 * gamma) + 0.000907 * math.sin(2 * gamma)

            # True solar time in minutes
            time_offset = eqtime + 4.0 * lon
            tst = dt.hour * 60.0 + dt.minute + dt.second / 60.0 + time_offset

            # Solar hour angle in degrees
            ha = (tst / 4.0) - 180.0

            lat_rad = math.radians(lat)
            ha_rad = math.radians(ha)

            # Solar zenith angle
            cos_zenith = math.sin(lat_rad) * math.sin(decl) + math.cos(lat_rad) * math.cos(decl) * math.cos(ha_rad)
            cos_zenith = max(-1.0, min(1.0, cos_zenith))
            zenith_rad = math.acos(cos_zenith)

            elevation_deg = 90.0 - math.degrees(zenith_rad)

            # Solar azimuth angle
            sin_zenith = math.sin(zenith_rad)
            if sin_zenith != 0:
                cos_azimuth = (math.sin(lat_rad) * math.cos(zenith_rad) - math.sin(decl)) / (math.cos(lat_rad) * sin_zenith)
                cos_azimuth = max(-1.0, min(1.0, cos_azimuth))
                azimuth_deg = 180.0 - math.degrees(math.acos(cos_azimuth))
                if ha > 0:
                    azimuth_deg = 360.0 - azimuth_deg
            else:
                azimuth_deg = 0.0

            return {
                "solar_elevation_degrees": round(elevation_deg, 2),
                "solar_azimuth_degrees": round(azimuth_deg, 2),
                "sun_visible": bool(elevation_deg > 0),
            }
        except Exception:
            return None
