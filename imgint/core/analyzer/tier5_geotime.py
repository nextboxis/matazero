"""Tier 5 Geospatial and Temporal Consistency Analyzer per SRD FR-6.1 - FR-6.8 and GR-4.4.

Enhanced with 6-point false-positive elimination:
  1. Coordinate Sanitization & Null Island Detection
  2. Distance-Capped & Hierarchical Reverse Geocoding
  3. Timezone-Aware Solar Chronolocation
  4. IANA Polygon-Based Timezone Consistency (replaces lon / 15.0 heuristic)
  5. Filesystem mtime Tolerance for Timezone Shifts
  6. Structured Location Confidence Scoring
"""

from __future__ import annotations
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from imgint.core.analyzer.base import Analyzer, AnalysisContext
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import Diagnostic
from imgint.core.geo.locator import GeoLocator
from imgint.core.geo.optical import OpticalRayCaster


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
        gps_satellites = ctx.get_field_value("GPSSatellites")
        gps_status = ctx.get_field_value("GPSStatus")
        gps_measure_mode = ctx.get_field_value("GPSMeasureMode")
        gps_diff = ctx.get_field_value("GPSDifferential")
        gps_img_dir = ctx.get_field_value("GPSImgDirection")
        gps_img_dir_ref = ctx.get_field_value("GPSImgDirectionRef") or "T"
        focal_len_raw = ctx.get_field_value("FocalLength")
        focal_len_35_raw = ctx.get_field_value("FocalLengthIn35mmFilm")
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

        # =====================================================================
        # IDEA 1: Coordinate Sanitization & Null Island Detection
        # =====================================================================
        coords_valid = False
        if lat_dec is not None and lon_dec is not None:
            coord_validation = GeoLocator.validate_coordinates(lat_dec, lon_dec)

            if not coord_validation["is_valid"]:
                # Emit a specialized finding instead of gps_coordinates_claimed
                lat_field = ctx.get_field("GPSLatitude")
                lon_field = ctx.get_field("GPSLongitude")

                findings.append(
                    Finding(
                        name="gps_fix_uninitialized",
                        value={
                            "latitude": round(lat_dec, 6),
                            "longitude": round(lon_dec, 6),
                            "validation_status": coord_validation["status"],
                            "validation_reason": coord_validation["reason"],
                        },
                        tier=5,
                        extractor="geotime_analyzer",
                        confidence=Confidence.INDICATIVE,
                        caveat=(
                            f"GPS coordinates failed validation: {coord_validation['reason']} "
                            "No reverse geocoding, solar chronolocation, or authenticity bonus will be applied. "
                            "This is NOT evidence of tampering — it commonly results from failed satellite locks, "
                            "privacy-stripping tools, or uninitialized device GPS modules (FR-6.8)."
                        ),
                        provenance=Provenance(
                            source_layer="analyzer",
                            extractor="geotime_analyzer",
                            offset=lat_field.value_offset if lat_field else None,
                            length=((lat_field.length or 0) if lat_field else 0) + ((lon_field.length or 0) if lon_field else 0),
                            standard="EXIF",
                        ),
                    )
                )
                diagnostics.append(
                    Diagnostic(
                        level="info",
                        message=f"GPS coordinates rejected ({coord_validation['status']}): {coord_validation['reason']}",
                        source="geotime_analyzer",
                    )
                )
                # DO NOT proceed with geocoding or solar computations
                lat_dec = None
                lon_dec = None
            else:
                coords_valid = True

        if coords_valid and lat_dec is not None and lon_dec is not None:
            lat_field = ctx.get_field("GPSLatitude")
            lon_field = ctx.get_field("GPSLongitude")
            y_loc = {
                "tag_offset": lat_field.offset if lat_field else None,
                "value_offset": lat_field.value_offset if lat_field else None,
                "length": lat_field.length if lat_field else None,
            }
            x_loc = {
                "tag_offset": lon_field.offset if lon_field else None,
                "value_offset": lon_field.value_offset if lon_field else None,
                "length": lon_field.length if lon_field else None,
            }

            findings.append(
                Finding(
                    name="gps_coordinates_claimed",
                    value={
                        "latitude": round(lat_dec, 6),
                        "longitude": round(lon_dec, 6),
                        "latitude_ref": lat_ref,
                        "longitude_ref": lon_ref,
                        "y": round(lat_dec, 6),
                        "x": round(lon_dec, 6),
                        "y_value_location": y_loc,
                        "x_value_location": x_loc,
                    },
                    tier=5,
                    extractor="geotime_analyzer",
                    confidence=Confidence.DERIVED,
                    caveat=(
                        "GPS coordinates reflect data recorded in image metadata by the device. "
                        "They can be manually edited, injected, or altered by third-party tools (FR-6.8)."
                    ),
                    provenance=Provenance(
                        source_layer="analyzer",
                        extractor="geotime_analyzer",
                        offset=lat_field.value_offset if lat_field else None,
                        length=((lat_field.length or 0) if lat_field else 0) + ((lon_field.length or 0) if lon_field else 0),
                        standard="EXIF",
                    ),
                )
            )

            # =================================================================
            # IDEA 2: Distance-Capped & Hierarchical Reverse Geocoding
            # =================================================================
            offline_place = GeoLocator.reverse_geocode_offline(lat_dec, lon_dec, max_distance_km=150.0)
            if offline_place:
                is_approx = offline_place.get("is_approximate", False)
                findings.append(
                    Finding(
                        name="offline_reverse_geocode",
                        value=offline_place,
                        tier=5,
                        extractor="offline_geocoder",
                        confidence=Confidence.DERIVED,
                        caveat=(
                            "Reverse geocoding performed using bundled offline GeoNames index (GR-4.4). "
                            + (
                                f"Result is APPROXIMATE: nearest indexed city is {offline_place.get('approx_distance_km', '?')}km away. "
                                "Country attribution may still be valid but city-level precision is low."
                                if is_approx
                                else "Represents closest administrative center."
                            )
                        ),
                        provenance=Provenance(source_layer="analyzer", extractor="offline_geocoder"),
                    )
                )

            # Facility Proximity Context (Airports, Ports) from Natural Earth DB
            facility_ctx = GeoLocator.get_facility_context(lat_dec, lon_dec, airport_max_km=50.0, port_max_km=30.0)
            if facility_ctx.get("has_facility_proximity"):
                findings.append(
                    Finding(
                        name="facility_proximity_context",
                        value=facility_ctx,
                        tier=5,
                        extractor="natural_earth_spatial",
                        confidence=Confidence.DERIVED,
                        caveat="Proximity to international/domestic airports or maritime seaports from Natural Earth spatial database.",
                        provenance=Provenance(source_layer="analyzer", extractor="natural_earth_spatial"),
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

        # Parse DOP for confidence scoring
        dop_value: Optional[float] = None
        if dop_raw:
            try:
                dop_value = self._convert_rational_to_float(dop_raw)
            except Exception:
                pass

        # GPS Sensor Telemetry & Hardware GNSS Integrity Analysis
        if coords_valid and lat_dec is not None and lon_dec is not None:
            telemetry: Dict[str, Any] = {
                "has_satellite_data": bool(gps_satellites),
                "satellites": str(gps_satellites) if gps_satellites else None,
                "status": str(gps_status) if gps_status else None,
                "measure_mode": str(gps_measure_mode) if gps_measure_mode else None,
                "differential": int(gps_diff) if gps_diff is not None else None,
                "has_altitude": bool(alt_raw),
                "has_timestamp": bool(gps_date and gps_time),
                "dop": dop_value,
            }
            integrity_score = 0.5
            signals: List[str] = []

            if gps_status in ("A", b"A", "Active"):
                integrity_score += 0.15
                signals.append("Active GNSS hardware fix confirmed (GPSStatus=A)")
            if gps_measure_mode in ("3", 3, b"3"):
                integrity_score += 0.15
                signals.append("3-Dimensional satellite triangulation lock (GPSMeasureMode=3)")
            if gps_satellites:
                integrity_score += 0.1
                signals.append(f"Satellite constellation telemetry present ({gps_satellites})")
            if dop_value and 0.5 <= dop_value <= 8.0:
                integrity_score += 0.1
                signals.append(f"Realistic dilution of precision recorded (DOP={dop_value})")

            telemetry["hardware_integrity_score"] = round(min(1.0, integrity_score), 2)
            telemetry["signals"] = signals
            telemetry["is_hardware_gnss_probable"] = integrity_score >= 0.75

            findings.append(
                Finding(
                    name="gps_sensor_telemetry_integrity",
                    value=telemetry,
                    tier=5,
                    extractor="geotime_analyzer",
                    confidence=Confidence.DERIVED,
                    caveat="Evaluation of GNSS receiver hardware telemetry to distinguish genuine chipsets from injected metadata.",
                    provenance=Provenance(source_layer="analyzer", extractor="geotime_analyzer"),
                )
            )


        # =====================================================================
        # IDEA 3: Timezone-Aware Solar Chronolocation
        # =====================================================================
        dt_capture = self._parse_datetime(date_orig)
        dt_capture_utc: Optional[datetime] = None

        if coords_valid and lat_dec is not None and lon_dec is not None and dt_capture is not None:
            # Resolve true UTC using IANA timezone lookup (instead of assuming UTC)
            dt_capture_utc = GeoLocator.resolve_capture_utc(
                str(date_orig), lat_dec, lon_dec, offset_str=offset_time
            )

            solar_pos = GeoLocator.compute_solar_chronolocation(
                lat_dec, lon_dec, dt_capture_utc or dt_capture
            )
            if solar_pos:
                # Add a note about how UTC was resolved
                utc_method = "explicit_offset" if offset_time else "iana_timezone_inference"
                solar_pos["utc_resolution_method"] = utc_method

                findings.append(
                    Finding(
                        name="solar_position_expected",
                        value=solar_pos,
                        tier=5,
                        extractor="solar_calculator",
                        confidence=Confidence.DERIVED,
                        caveat=(
                            "Expected solar azimuth and elevation computed using NOAA/Astral algorithms from claimed GPS and timestamp. "
                            f"UTC resolution method: {utc_method}. "
                            + (
                                "Capture time was localized using IANA timezone polygon lookup from GPS coordinates "
                                "(OffsetTimeOriginal was absent in metadata). "
                                if utc_method == "iana_timezone_inference"
                                else ""
                            )
                            + "Provided for analyst comparison against visible shadow geometry."
                        ),
                        provenance=Provenance(source_layer="analyzer", extractor="solar_calculator"),
                    )
                )

                # Astronomical Physical Shadow Geometry Analysis
                solar_el = solar_pos.get("solar_elevation_degrees", 0.0)
                solar_az = solar_pos.get("solar_azimuth_degrees", 0.0)
                if solar_el > 0.5:
                    import math
                    el_rad = math.radians(solar_el)
                    shadow_mult = 1.0 / math.tan(el_rad)
                    shadow_bearing = (solar_az + 180.0) % 360.0

                    shadow_data = {
                        "solar_elevation_degrees": round(solar_el, 2),
                        "solar_azimuth_degrees": round(solar_az, 2),
                        "shadow_bearing_degrees": round(shadow_bearing, 2),
                        "shadow_length_multiplier": round(shadow_mult, 3),
                        "expected_shadow_lengths_meters": {
                            "standing_human_1_8m": round(1.8 * shadow_mult, 2),
                            "utility_pole_5_0m": round(5.0 * shadow_mult, 2),
                            "structure_10_0m": round(10.0 * shadow_mult, 2),
                        },
                        "day_phase": solar_pos.get("day_phase"),
                    }
                    findings.append(
                        Finding(
                            name="astronomical_shadow_geometry",
                            value=shadow_data,
                            tier=5,
                            extractor="solar_calculator",
                            confidence=Confidence.DERIVED,
                            caveat="Computed ground shadow bearing and length multiplier for authenticating physical outdoor shadows and detecting synthetic/composite subjects.",
                            provenance=Provenance(source_layer="analyzer", extractor="solar_calculator"),
                        )
                    )

        # Optical Viewing Cone & Camera Sightline Frustum
        if coords_valid and lat_dec is not None and lon_dec is not None and gps_img_dir is not None:
            try:
                img_dir_val = self._convert_rational_to_float(gps_img_dir)
                f_mm = self._convert_rational_to_float(focal_len_raw) if focal_len_raw else None
                f_35 = self._convert_rational_to_float(focal_len_35_raw) if focal_len_35_raw else None

                cone = OpticalRayCaster.calculate_viewing_cone(
                    lat=lat_dec,
                    lon=lon_dec,
                    heading_deg=img_dir_val,
                    heading_ref=str(gps_img_dir_ref),
                    focal_length_35mm=f_35,
                    focal_length_mm=f_mm,
                    viewing_distance_meters=300.0,
                )
                findings.append(
                    Finding(
                        name="optical_viewing_cone",
                        value=cone.to_dict(),
                        tier=5,
                        extractor="optical_raycaster",
                        confidence=Confidence.DERIVED,
                        caveat="Camera optical sightline and field-of-view viewing cone projected onto terrain from compass heading and lens focal length.",
                        provenance=Provenance(source_layer="analyzer", extractor="optical_raycaster"),
                    )
                )
            except Exception:
                pass

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

        # =====================================================================
        # IDEA 4: IANA Polygon-Based Timezone Consistency
        # (Replaces the crude lon / 15.0 heuristic that false-flagged China, Spain, etc.)
        # =====================================================================
        if offset_time and coords_valid and lon_dec is not None and lat_dec is not None:
            try:
                sign = -1 if offset_time.startswith("-") else 1
                parts = offset_time.lstrip("+-").split(":")
                hours = int(parts[0]) + (int(parts[1]) / 60.0 if len(parts) > 1 else 0)
                claimed_tz_offset = sign * hours

                # Resolve the IANA timezone for this location
                iana_zone = GeoLocator.get_timezone(lat_dec, lon_dec)

                if iana_zone:
                    # Check if the claimed offset is valid for this specific IANA zone
                    is_valid_offset = GeoLocator.is_offset_valid_for_zone(iana_zone, claimed_tz_offset)

                    if not is_valid_offset:
                        # Get the list of valid offsets for the diagnostic message
                        valid_offsets = GeoLocator.get_valid_utc_offsets_for_zone(iana_zone)
                        findings.append(
                            Finding(
                                name="timezone_longitude_inconsistency",
                                value={
                                    "claimed_offset_hours": claimed_tz_offset,
                                    "iana_timezone": iana_zone,
                                    "valid_offsets_for_zone": valid_offsets,
                                    "validation_method": "iana_polygon_lookup",
                                },
                                tier=5,
                                extractor="temporal_crosscheck",
                                confidence=Confidence.INDICATIVE,
                                caveat=(
                                    f"Claimed timezone offset UTC{claimed_tz_offset:+.1f} is not a valid offset "
                                    f"for IANA timezone '{iana_zone}' (valid: {valid_offsets}). "
                                    "This may indicate the photo was taken in a different location than the GPS claims, "
                                    "or the device timezone was manually set to a foreign timezone while traveling."
                                ),
                                provenance=Provenance(source_layer="analyzer", extractor="temporal_crosscheck"),
                            )
                        )
                else:
                    # Fallback: cannot resolve IANA zone, use permissive solar offset as last resort
                    expected_tz_approx = lon_dec / 15.0
                    diff = abs(claimed_tz_offset - expected_tz_approx)
                    if diff > 4.0:  # Wider tolerance than before (was 3.0)
                        findings.append(
                            Finding(
                                name="timezone_longitude_inconsistency",
                                value={
                                    "claimed_offset_hours": claimed_tz_offset,
                                    "expected_solar_offset_approx": round(expected_tz_approx, 1),
                                    "discrepancy_hours": round(diff, 1),
                                    "validation_method": "solar_longitude_fallback",
                                },
                                tier=5,
                                extractor="temporal_crosscheck",
                                confidence=Confidence.INCONCLUSIVE,
                                caveat=(
                                    "IANA timezone data unavailable for this location. "
                                    "Falling back to approximate solar longitude offset comparison. "
                                    "This is inherently imprecise and should not be treated as strong evidence."
                                ),
                                provenance=Provenance(source_layer="analyzer", extractor="temporal_crosscheck"),
                            )
                        )
            except Exception:
                pass

        # =====================================================================
        # IDEA 5: Filesystem mtime Tolerance for Timezone Shifts
        # (Eliminates false positives from archive extraction and timezone conversions)
        # =====================================================================
        try:
            mtime_epoch = ctx.file_path.stat().st_mtime
            if dt_capture:
                capture_epoch = (dt_capture_utc or dt_capture).timestamp()
                delta_seconds = mtime_epoch - capture_epoch

                if delta_seconds < -60:  # mtime precedes capture time
                    # Check if the discrepancy aligns with a timezone offset boundary.
                    # Timezone offsets come in 15-minute granularity (UTC+5:30, UTC+5:45, etc.)
                    abs_delta = abs(delta_seconds)
                    remainder_15min = abs_delta % 900  # 900 seconds = 15 minutes
                    is_timezone_shift = remainder_15min < 120 or remainder_15min > 780  # Within 2 min of a 15-min boundary

                    if is_timezone_shift and abs_delta < 86400:  # Less than 24 hours and timezone-aligned
                        # This is almost certainly a timezone conversion artifact, not timestomping
                        diagnostics.append(
                            Diagnostic(
                                level="info",
                                message=(
                                    f"Filesystem mtime precedes capture time by {abs(round(delta_seconds))}s "
                                    f"({round(abs_delta / 3600.0, 1)}h), which aligns with an exact timezone "
                                    f"offset boundary. Suppressed as likely timezone conversion artifact."
                                ),
                                source="temporal_crosscheck",
                            )
                        )
                    else:
                        # Genuine anomaly: non-hour-aligned or very large delta
                        findings.append(
                            Finding(
                                name="filesystem_mtime_precedes_capture",
                                value={
                                    "filesystem_mtime_utc": datetime.fromtimestamp(mtime_epoch, timezone.utc).isoformat(),
                                    "claimed_capture_time_utc": (dt_capture_utc or dt_capture).isoformat(),
                                    "delta_seconds": round(delta_seconds, 1),
                                    "is_hour_aligned": False,
                                },
                                tier=5,
                                extractor="temporal_crosscheck",
                                confidence=Confidence.INDICATIVE,
                                caveat=(
                                    "Filesystem modification time precedes claimed capture time by a "
                                    "non-hour-aligned interval. Less likely to be a timezone conversion artifact. "
                                    "May indicate timestomping, archive extraction with modified timestamps, "
                                    "or camera clock errors."
                                ),
                                provenance=Provenance(source_layer="analyzer", extractor="temporal_crosscheck"),
                            )
                        )
        except Exception:
            pass

        # =====================================================================
        # IDEA 6: Location Confidence Scoring
        # =====================================================================
        if coords_valid and lat_dec is not None and lon_dec is not None:
            # Gather signals for confidence computation
            has_gps_ts = bool(gps_date and gps_time)

            solar_el: Optional[float] = None
            day_ph: Optional[str] = None
            solar_finding = next((f for f in findings if f.name == "solar_position_expected"), None)
            if solar_finding and isinstance(solar_finding.value, dict):
                solar_el = solar_finding.value.get("solar_elevation_degrees")
                day_ph = solar_finding.value.get("day_phase")

            loc_confidence = GeoLocator.compute_location_confidence(
                lat=lat_dec,
                lon=lon_dec,
                dop=dop_value,
                has_gps_timestamp=has_gps_ts,
                solar_elevation=solar_el,
                day_phase=day_ph,
            )

            findings.append(
                Finding(
                    name="gps_location_confidence",
                    value=loc_confidence,
                    tier=5,
                    extractor="geotime_analyzer",
                    confidence=Confidence.DERIVED,
                    caveat=(
                        f"Location confidence level: {loc_confidence['level']} (score: {loc_confidence['score']}). "
                        "Computed from coordinate validity, satellite time presence, dilution of precision, "
                        "and solar position consistency. HIGH confidence requires multiple corroborating signals."
                    ),
                    provenance=Provenance(source_layer="analyzer", extractor="geotime_analyzer"),
                )
            )

        return findings, diagnostics

    def _convert_dms_to_decimal(self, dms_raw: Any, ref: str) -> float:
        if isinstance(dms_raw, (int, float)):
            val = float(dms_raw)
            if ref in ("S", "W"):
                val = -val
            return val

        if isinstance(dms_raw, (list, tuple)) and len(dms_raw) >= 3:
            deg = self._convert_rational_to_float(dms_raw[0])
            mins = self._convert_rational_to_float(dms_raw[1])
            secs = self._convert_rational_to_float(dms_raw[2])
            dec = deg + (mins / 60.0) + (secs / 3600.0)
            if ref in ("S", "W"):
                dec = -dec
            return dec
        raise ValueError(f"Unrecognized DMS structure {dms_raw}")

    def _convert_rational_to_float(self, val: Any) -> float:
        if isinstance(val, (list, tuple)) and len(val) == 2:
            num, den = val
            return float(num) / float(den) if den != 0 else float(num)
        return float(val)

    def _offline_reverse_geocode(self, lat: float, lon: float) -> Optional[Dict[str, Any]]:
        return GeoLocator.reverse_geocode_offline(lat, lon)

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
        return GeoLocator._compute_noaa_solar_position(lat, lon, dt)
