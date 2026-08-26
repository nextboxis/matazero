"""Unit tests for GeoLocator, GeoExporter, and Geolocation packages."""

import json
from datetime import datetime, timezone
from pathlib import Path
from imgint.core.geo.locator import GeoLocator
from imgint.core.geo.exporter import GeoExporter


def test_timezone_finder():
    # New York coordinates
    tz_ny = GeoLocator.get_timezone(40.7128, -74.0060)
    assert tz_ny in ("America/New_York", "EST", "EDT") or "New_York" in str(tz_ny)

    # Tokyo coordinates
    tz_tokyo = GeoLocator.get_timezone(35.6762, 139.6503)
    assert tz_tokyo in ("Asia/Tokyo", "JST") or "Tokyo" in str(tz_tokyo)

    # London coordinates
    tz_london = GeoLocator.get_timezone(51.5074, -0.1278)
    assert tz_london in ("Europe/London", "GMT", "BST") or "London" in str(tz_london)


def test_distance_and_bearing():
    # Distance between London and Paris (~343 km)
    london = (51.5074, -0.1278)
    paris = (48.8566, 2.3522)

    dist = GeoLocator.compute_distance(london[0], london[1], paris[0], paris[1])
    assert 330 <= dist["distance_km"] <= 360
    assert dist["distance_miles"] > 200

    bearing = GeoLocator.compute_bearing(london[0], london[1], paris[0], paris[1])
    # London to Paris is South-East (~140 - 160 degrees)
    assert 130 <= bearing["bearing_degrees"] <= 170
    assert "S" in bearing["cardinal_direction"] or "E" in bearing["cardinal_direction"]


def test_solar_chronolocation():
    # London at summer noon
    dt = datetime(2026, 6, 21, 12, 0, 0, tzinfo=timezone.utc)
    solar = GeoLocator.compute_solar_chronolocation(51.5074, -0.1278, dt)

    assert solar["solar_elevation_degrees"] > 50.0
    assert solar["sun_visible"] is True
    assert solar["day_phase"] == "Daylight"
    assert solar["shadow_length_factor"] is not None

    # London at midnight
    dt_night = datetime(2026, 6, 21, 0, 0, 0, tzinfo=timezone.utc)
    solar_night = GeoLocator.compute_solar_chronolocation(51.5074, -0.1278, dt_night)
    assert solar_night["solar_elevation_degrees"] < 0.0
    assert solar_night["sun_visible"] is False


def test_offline_reverse_geocoding():
    # Near San Francisco
    res = GeoLocator.reverse_geocode_offline(37.7749, -122.4194)
    assert res is not None
    assert res["closest_city"] == "San Francisco"
    assert res["country"] == "United States"

    # Near Berlin
    res_de = GeoLocator.reverse_geocode_offline(52.5200, 13.4050)
    assert res_de is not None
    assert res_de["closest_city"] == "Berlin"
    assert res_de["country"] == "Germany"


def test_geo_exporter_geojson_html_gpx():
    sample_points = [
        {
            "file_name": "photo1.jpg",
            "latitude": 40.7128,
            "longitude": -74.0060,
            "timestamp": "2026-08-26T12:00:00Z",
            "closest_city": "New York City",
            "country": "United States",
            "altitude_m": 15.0,
            "sha256": "abcdef1234567890abcdef1234567890",
        },
        {
            "file_name": "photo2.jpg",
            "latitude": 40.7580,
            "longitude": -73.9855,
            "timestamp": "2026-08-26T12:30:00Z",
            "closest_city": "New York City",
            "country": "United States",
            "altitude_m": 22.0,
            "sha256": "1234567890abcdef1234567890abcdef",
        },
    ]

    # Test GeoJSON
    geojson = GeoExporter.to_geojson(sample_points)
    assert geojson["type"] == "FeatureCollection"
    assert len(geojson["features"]) == 3  # 2 points + 1 LineString
    assert "bbox" in geojson

    # Test Leaflet HTML
    html = GeoExporter.to_leaflet_html(sample_points)
    assert "<!DOCTYPE html>" in html
    assert "L.map('map'" in html
    assert "photo1.jpg" in html
    assert "photo2.jpg" in html

    # Test GPX
    gpx = GeoExporter.to_gpx(sample_points)
    assert '<?xml version="1.0" encoding="UTF-8"?>' in gpx
    assert "<trkpt" in gpx
    assert 'lat="40.712800"' in gpx


if __name__ == "__main__":
    print("Running test_timezone_finder...")
    test_timezone_finder()
    print("Running test_distance_and_bearing...")
    test_distance_and_bearing()
    print("Running test_solar_chronolocation...")
    test_solar_chronolocation()
    print("Running test_offline_reverse_geocoding...")
    test_offline_reverse_geocoding()
    print("Running test_geo_exporter_geojson_html_gpx...")
    test_geo_exporter_geojson_html_gpx()
    print("ALL GEOLOCATOR & EXPORTER UNIT TESTS PASSED!")
