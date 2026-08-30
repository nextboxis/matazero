"""Tests for Geospatial solar chronolocation and GeoJSON/GPX/Leaflet export."""

import pytest
from datetime import datetime, timezone
from pathlib import Path
from imgint.core.geo.locator import GeoLocator
from imgint.core.geo.exporter import GeoExporter


def test_solar_chronolocation_equator_noon():
    # Test solar position on Equator at Vernal Equinox (March 20, 12:00 UTC) at longitude 0.0
    dt = datetime(2026, 3, 20, 12, 0, 0, tzinfo=timezone.utc)
    solar_info = GeoLocator.compute_solar_chronolocation(0.0, 0.0, dt)

    assert solar_info is not None
    assert "solar_elevation_degrees" in solar_info
    assert "solar_azimuth_degrees" in solar_info
    # Solar elevation should be near 90 degrees at solar noon on the equator
    assert 80.0 <= solar_info["solar_elevation_degrees"] <= 90.0


def test_geo_exporter_geojson(tmp_path):
    points = [
        {
            "file_name": "photo1.jpg",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "altitude_m": 15.0,
            "timestamp": "2026-08-30T10:00:00Z",
        }
    ]
    geojson_doc = GeoExporter.to_geojson(points)

    assert geojson_doc["type"] == "FeatureCollection"
    assert len(geojson_doc["features"]) == 1
    assert geojson_doc["features"][0]["geometry"]["coordinates"] == [-122.4194, 37.7749]


def test_geo_exporter_gpx(tmp_path):
    points = [
        {
            "file_name": "photo2.jpg",
            "latitude": 40.7128,
            "longitude": -74.0060,
            "altitude_m": 10.0,
        }
    ]
    gpx_str = GeoExporter.to_gpx(points)

    assert "<gpx" in gpx_str
    assert 'lat="40.712800"' in gpx_str
    assert 'lon="-74.006000"' in gpx_str


def test_geo_exporter_html_map(tmp_path):
    points = [
        {
            "file_name": "photo3.jpg",
            "latitude": 51.5074,
            "longitude": -0.1278,
        }
    ]
    html_str = GeoExporter.to_leaflet_html(points)

    assert "leaflet" in html_str.lower()
    assert "51.5074" in html_str
