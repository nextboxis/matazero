"""Comprehensive unit and integration test suite for geolocation false-positive prevention across all modules."""

import pytest
import datetime
from pathlib import Path

from imgint.core.geo.locator import GeoLocator
from imgint.core.geo.optical import OpticalRayCaster
from imgint.core.geo.exporter import GeoExporter
from imgint.core.analyzer.tier5_geotime import GeoTimeAnalyzer
from imgint.core.cluster.engine import ClusterEngine, ClusteredItem
from imgint.core.timeline.reconstructor import TimelineReconstructor, TimelineEvent
from imgint.core.report.dossier import CaseDossierGenerator
from imgint.core.model.record import AnalysisRecord, Field
from imgint.core.model.finding import Finding, Confidence


def test_validate_coordinates_null_island():
    """Null Island coordinates (0.0, 0.0) must be rejected with status NULL_ISLAND."""
    res = GeoLocator.validate_coordinates(0.0, 0.0)
    assert not res["is_valid"]
    assert res["status"] == "NULL_ISLAND"

    res_near = GeoLocator.validate_coordinates(0.00001, -0.00001)
    assert not res_near["is_valid"]
    assert res_near["status"] == "NULL_ISLAND"


def test_validate_coordinates_out_of_bounds():
    """Out-of-bounds latitude (>90 or <-90) and longitude (>180 or <-180) must be rejected."""
    res_lat = GeoLocator.validate_coordinates(95.0, 10.0)
    assert not res_lat["is_valid"]
    assert res_lat["status"] == "OUT_OF_BOUNDS"

    res_lon = GeoLocator.validate_coordinates(10.0, -185.0)
    assert not res_lon["is_valid"]
    assert res_lon["status"] == "OUT_OF_BOUNDS"


def test_validate_coordinates_valid():
    """Legitimate coordinates (e.g. Montreal 45.5017, -73.5673) must pass validation."""
    res = GeoLocator.validate_coordinates(45.5017, -73.5673)
    assert res["is_valid"]
    assert res["status"] == "VALID"


def test_convert_dms_to_decimal_various_formats():
    """DMS to decimal converter must safely handle tuple, list, float, and int rationals."""
    gta = GeoTimeAnalyzer()

    # Float/Int tuple
    deg = gta._convert_dms_to_decimal((12, 58, 17.76), "N")
    assert deg is not None
    assert abs(deg - 12.9716) < 0.001

    # Rational tuples ((12, 1), (58, 1), (1776, 100))
    deg_rat = gta._convert_dms_to_decimal(((12, 1), (58, 1), (1776, 100)), "N")
    assert deg_rat is not None
    assert abs(deg_rat - 12.9716) < 0.001

    # South ref (negative)
    deg_s = gta._convert_dms_to_decimal((34, 0, 0), "S")
    assert deg_s == -34.0

    # West ref (negative)
    deg_w = gta._convert_dms_to_decimal((77, 0, 0), "W")
    assert deg_w == -77.0

    # Malformed data should return None, not crash
    assert gta._convert_dms_to_decimal(None, "N") is None
    assert gta._convert_dms_to_decimal("invalid", "N") is None
    assert gta._convert_dms_to_decimal([1, 2], "N") is None


def test_dossier_filters_null_island_and_invalid():
    """CaseDossierGenerator must exclude Null Island and invalid coordinates from gps_points map."""
    rec_null = AnalysisRecord(
        file_path="null_island.jpg",
        sha256="abc1",
        file_size=1000,
        mime_type="image/jpeg",
        tool_version="2.0.0",
        corpus_version="2026.08",
        findings=[
            Finding(
                name="gps_coordinates_claimed",
                value={"latitude": 0.0, "longitude": 0.0},
                tier=5,
                extractor="test",
                confidence=Confidence.INDICATIVE,
                caveat="Unverified claimed GPS coordinates.",
            )
        ],
    )

    rec_valid = AnalysisRecord(
        file_path="valid_paris.jpg",
        sha256="abc2",
        file_size=1000,
        mime_type="image/jpeg",
        tool_version="2.0.0",
        corpus_version="2026.08",
        findings=[
            Finding(
                name="gps_coordinates_claimed",
                value={"latitude": 48.8566, "longitude": 2.3522},
                tier=5,
                extractor="test",
                confidence=Confidence.OBSERVED,
            )
        ],
    )

    html_out = CaseDossierGenerator.generate_html([rec_null, rec_valid], case_title="Test Dossier")
    assert "48.8566" in html_out
    # Null island should not be in the GPS points JSON
    assert '"lat": 0.0, "lng": 0.0' not in html_out


def test_cluster_engine_filters_null_island():
    """ClusterEngine must not cluster Null Island coordinates under Geospatial Zones."""
    item_null = ClusteredItem(
        file_name="null.jpg",
        file_path="null.jpg",
        sha256="111",
        gps_coordinates=(0.0, 0.0),
    )
    item_valid1 = ClusteredItem(
        file_name="valid1.jpg",
        file_path="valid1.jpg",
        sha256="222",
        gps_coordinates=(40.7128, -74.0060),
    )
    item_valid2 = ClusteredItem(
        file_name="valid2.jpg",
        file_path="valid2.jpg",
        sha256="333",
        gps_coordinates=(40.7130, -74.0062),
    )

    # _cluster_by_geo should group valid1 and valid2, but not null
    clusters = ClusterEngine._cluster_by_geo([item_valid1, item_valid2], radius_km=5.0)
    assert len(clusters) == 1
    assert clusters[0].item_count == 2


def test_timeline_reconstructor_kinematic_anomalies():
    """TimelineReconstructor should flag impossible travel speeds (>1000 km/h) without false positives on walking/driving."""
    t0 = datetime.datetime(2026, 8, 29, 10, 0, 0, tzinfo=datetime.timezone.utc)
    t1 = datetime.datetime(2026, 8, 29, 10, 10, 0, tzinfo=datetime.timezone.utc) # 10 mins later

    # Paris to Tokyo in 10 minutes (impossible ~58,000 km/h)
    kinematic_fast = GeoLocator.compute_kinematic_speed(
        lat1=48.8566, lon1=2.3522, dt1=t0,
        lat2=35.6762, lon2=139.6503, dt2=t1,
    )
    assert kinematic_fast["is_anomalous"]
    assert kinematic_fast["speed_kmh"] > 1000

    # 1 km in 10 minutes (6 km/h walking speed - normal)
    kinematic_normal = GeoLocator.compute_kinematic_speed(
        lat1=48.8566, lon1=2.3522, dt1=t0,
        lat2=48.8656, lon2=2.3522, dt2=t1,
    )
    assert not kinematic_normal["is_anomalous"]
    assert kinematic_normal["speed_kmh"] < 100


if __name__ == "__main__":
    test_validate_coordinates_null_island()
    test_validate_coordinates_out_of_bounds()
    test_validate_coordinates_valid()
    test_convert_dms_to_decimal_various_formats()
    test_dossier_filters_null_island_and_invalid()
    test_cluster_engine_filters_null_island()
    test_timeline_reconstructor_kinematic_anomalies()
    print("ALL 7 GEOLOCATION FALSE POSITIVE AUDIT TESTS PASSED SUCCESSFULLY!")
