"""Forensic-grade Geolocation Intelligence and Chronolocation Engine.

Supports offline spatial KD-Tree lookups, timezone resolution via TimezoneFinder,
geodesic distance/bearing calculation via Geopy, and astronomical solar chronolocation via Astral/NOAA.
"""

from __future__ import annotations
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Optional high-performance packages with resilient internal fallbacks
try:
    from timezonefinder import TimezoneFinder
    _TZ_FINDER: Optional[TimezoneFinder] = TimezoneFinder()
except Exception:
    _TZ_FINDER = None

try:
    import geopy.distance
    from geopy.geocoders import Nominatim
    _HAS_GEOPY = True
except Exception:
    _HAS_GEOPY = False

try:
    import astral
    from astral.sun import sun
    from astral import LocationInfo
    _HAS_ASTRAL = True
except Exception:
    _HAS_ASTRAL = False


COMPASS_DIRECTIONS = [
    "N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE",
    "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"
]


class GeoLocator:
    """Unified Geolocation, Reverse Geocoding, and Solar Chronolocation Service."""

    _cached_places: Optional[List[Dict[str, Any]]] = None

    @classmethod
    def load_offline_database(cls) -> List[Dict[str, Any]]:
        """Loads and caches the bundled offline GeoNames dataset."""
        if cls._cached_places is not None:
            return cls._cached_places

        data_file = Path(__file__).parent.parent / "data" / "geonames_offline.json"
        if not data_file.exists():
            cls._cached_places = []
            return cls._cached_places

        try:
            with open(data_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                cls._cached_places = data.get("places", [])
        except Exception:
            cls._cached_places = []
        return cls._cached_places

    @classmethod
    def get_timezone(cls, lat: float, lon: float) -> Optional[str]:
        """Resolves IANA timezone name (e.g. 'America/New_York') from coordinates."""
        # 1. Try TimezoneFinder polygon lookup
        if _TZ_FINDER is not None:
            try:
                tz_name = _TZ_FINDER.timezone_at(lat=lat, lng=lon)
                if tz_name:
                    return tz_name
            except Exception:
                pass

        # 2. Fall back to closest offline database place
        closest = cls.reverse_geocode_offline(lat, lon)
        if closest and closest.get("timezone"):
            return closest["timezone"]

        # 3. Fall back to approximate solar timezone offset string
        approx_offset = round(lon / 15.0)
        sign = "+" if approx_offset >= 0 else "-"
        return f"Etc/GMT{sign}{abs(approx_offset)}"

    @classmethod
    def reverse_geocode_offline(cls, lat: float, lon: float) -> Optional[Dict[str, Any]]:
        """Performs nearest-neighbor offline reverse geocoding against bundled database."""
        places = cls.load_offline_database()
        if not places:
            return None

        best_place = None
        min_dist_km = float("inf")

        for p in places:
            plat = p.get("lat")
            plon = p.get("lon")
            if plat is None or plon is None:
                continue

            dist = cls.compute_haversine_distance(lat, lon, plat, plon)
            if dist < min_dist_km:
                min_dist_km = dist
                best_place = p

        if best_place:
            tz = best_place.get("timezone") or cls.get_timezone(lat, lon)
            return {
                "closest_city": best_place.get("name"),
                "admin_region": best_place.get("admin1"),
                "country": best_place.get("country"),
                "country_code": best_place.get("country_code", ""),
                "timezone": tz,
                "approx_distance_km": round(min_dist_km, 2),
                "approx_distance_miles": round(min_dist_km * 0.621371, 2),
            }
        return None

    @classmethod
    def reverse_geocode_online(
        cls, lat: float, lon: float, user_agent: str = "matazero_forensic_geolocator/2.0"
    ) -> Optional[Dict[str, Any]]:
        """Performs high-detail online reverse geocoding via OpenStreetMap / Nominatim (GR-4.1 network opt-in)."""
        if not _HAS_GEOPY:
            return None

        try:
            geolocator = Nominatim(user_agent=user_agent, timeout=5)
            location = geolocator.reverse((lat, lon), exactly_one=True, language="en")
            if not location:
                return None

            raw = location.raw or {}
            addr = raw.get("address", {})
            return {
                "display_name": location.address,
                "road": addr.get("road") or addr.get("pedestrian"),
                "suburb": addr.get("suburb") or addr.get("neighbourhood"),
                "city": addr.get("city") or addr.get("town") or addr.get("village"),
                "state": addr.get("state") or addr.get("region"),
                "country": addr.get("country"),
                "country_code": addr.get("country_code", "").upper(),
                "postcode": addr.get("postcode"),
                "osm_id": raw.get("osm_id"),
                "osm_type": raw.get("osm_type"),
            }
        except Exception:
            return None

    @classmethod
    def compute_distance(cls, lat1: float, lon1: float, lat2: float, lon2: float) -> Dict[str, float]:
        """Computes geodesic and great-circle distance between two points."""
        if _HAS_GEOPY:
            try:
                p1 = (lat1, lon1)
                p2 = (lat2, lon2)
                km_geodesic = geopy.distance.geodesic(p1, p2).kilometers
                km_great_circle = geopy.distance.great_circle(p1, p2).kilometers
                return {
                    "distance_km": round(km_geodesic, 3),
                    "distance_miles": round(km_geodesic * 0.621371, 3),
                    "distance_nautical_miles": round(km_geodesic * 0.539957, 3),
                    "distance_meters": round(km_geodesic * 1000.0, 1),
                }
            except Exception:
                pass

        km = cls.compute_haversine_distance(lat1, lon1, lat2, lon2)
        return {
            "distance_km": round(km, 3),
            "distance_miles": round(km * 0.621371, 3),
            "distance_nautical_miles": round(km * 0.539957, 3),
            "distance_meters": round(km * 1000.0, 1),
        }

    @staticmethod
    def compute_haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Great-circle distance using Haversine formula on WGS-84 mean earth radius (6,371 km)."""
        r = 6371.0
        d_lat = math.radians(lat2 - lat1)
        d_lon = math.radians(lon2 - lon1)
        a = (
            math.sin(d_lat / 2.0) ** 2
            + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(d_lon / 2.0) ** 2
        )
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return r * c

    @staticmethod
    def compute_bearing(lat1: float, lon1: float, lat2: float, lon2: float) -> Dict[str, Any]:
        """Calculates initial geodesic forward bearing in degrees and compass cardinal point."""
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_lambda = math.radians(lon2 - lon1)

        y = math.sin(delta_lambda) * math.cos(phi2)
        x = math.cos(phi1) * math.sin(phi2) - math.sin(phi1) * math.cos(phi2) * math.cos(delta_lambda)
        theta = math.atan2(y, x)
        bearing = (math.degrees(theta) + 360.0) % 360.0

        # Compass direction (16-point wind rose)
        idx = int((bearing + 11.25) / 22.5) % 16
        cardinal = COMPASS_DIRECTIONS[idx]

        return {
            "bearing_degrees": round(bearing, 2),
            "cardinal_direction": cardinal,
        }

    @classmethod
    def compute_solar_chronolocation(
        cls, lat: float, lon: float, dt: datetime
    ) -> Dict[str, Any]:
        """Computes solar elevation, azimuth, dawn/dusk, and daylight state for shadow validation."""
        # Ensure UTC timezone aware datetime
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)

        result: Dict[str, Any] = {
            "solar_elevation_degrees": 0.0,
            "solar_azimuth_degrees": 0.0,
            "sun_visible": False,
            "shadow_length_factor": None,
            "day_phase": "Night",
        }

        # 1. Try Astral if installed
        if _HAS_ASTRAL:
            try:
                loc = LocationInfo(name="Target", region="Unknown", timezone="UTC", latitude=lat, longitude=lon)
                s = sun(loc.observer, date=dt.date(), tzinfo=timezone.utc)
                az = astral.sun.azimuth(loc.observer, dt)
                el = astral.sun.elevation(loc.observer, dt)

                result["solar_azimuth_degrees"] = round(az, 2)
                result["solar_elevation_degrees"] = round(el, 2)
                result["sun_visible"] = bool(el > 0.0)

                if el > 0.0:
                    rad = math.radians(el)
                    shadow_factor = 1.0 / math.tan(rad) if math.tan(rad) != 0 else 0.0
                    result["shadow_length_factor"] = round(shadow_factor, 2)

                # Solar events
                result["sunrise_utc"] = s["sunrise"].strftime("%H:%M:%S")
                result["sunset_utc"] = s["sunset"].strftime("%H:%M:%S")
                result["noon_utc"] = s["noon"].strftime("%H:%M:%S")
                result["dawn_utc"] = s["dawn"].strftime("%H:%M:%S")
                result["dusk_utc"] = s["dusk"].strftime("%H:%M:%S")

                if el > 6.0:
                    result["day_phase"] = "Daylight"
                elif 0.0 < el <= 6.0:
                    result["day_phase"] = "Golden Hour"
                elif -6.0 <= el <= 0.0:
                    result["day_phase"] = "Civil Twilight / Blue Hour"
                elif -12.0 <= el < -6.0:
                    result["day_phase"] = "Nautical Twilight"
                elif -18.0 <= el < -12.0:
                    result["day_phase"] = "Astronomical Twilight"
                else:
                    result["day_phase"] = "Night"

                return result
            except Exception:
                pass

        # 2. NOAA Standard Algorithm Fallback
        noaa = cls._compute_noaa_solar_position(lat, lon, dt)
        if noaa:
            result.update(noaa)
            el = noaa["solar_elevation_degrees"]
            if el > 0:
                rad = math.radians(el)
                shadow_factor = 1.0 / math.tan(rad) if math.tan(rad) != 0 else 0.0
                result["shadow_length_factor"] = round(shadow_factor, 2)
                result["day_phase"] = "Daylight" if el > 6.0 else "Golden Hour"
            else:
                result["day_phase"] = "Civil Twilight" if el >= -6.0 else "Night"

        return result

    @staticmethod
    def _compute_noaa_solar_position(lat: float, lon: float, dt: datetime) -> Optional[Dict[str, Any]]:
        """NOAA solar position approximation algorithm."""
        try:
            day_of_year = dt.timetuple().tm_yday
            hour_float = dt.hour + dt.minute / 60.0 + dt.second / 3600.0

            gamma = 2.0 * math.pi / 365.0 * (day_of_year - 1 + (hour_float - 12.0) / 24.0)
            eqtime = 229.18 * (
                0.000075 + 0.001868 * math.cos(gamma) - 0.032077 * math.sin(gamma)
                - 0.014615 * math.cos(2 * gamma) - 0.040849 * math.sin(2 * gamma)
            )
            decl = (
                0.006918 - 0.399912 * math.cos(gamma) + 0.070257 * math.sin(gamma)
                - 0.006758 * math.cos(2 * gamma) + 0.000907 * math.sin(2 * gamma)
            )

            time_offset = eqtime + 4.0 * lon
            tst = dt.hour * 60.0 + dt.minute + dt.second / 60.0 + time_offset
            ha = (tst / 4.0) - 180.0

            lat_rad = math.radians(lat)
            ha_rad = math.radians(ha)

            cos_zenith = math.sin(lat_rad) * math.sin(decl) + math.cos(lat_rad) * math.cos(decl) * math.cos(ha_rad)
            cos_zenith = max(-1.0, min(1.0, cos_zenith))
            zenith_rad = math.acos(cos_zenith)

            elevation_deg = 90.0 - math.degrees(zenith_rad)

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

    @staticmethod
    def get_map_links(lat: float, lon: float) -> Dict[str, str]:
        """Generates direct browser links for popular interactive mapping platforms."""
        lat_f = f"{lat:.6f}"
        lon_f = f"{lon:.6f}"
        lat_card = "N" if lat >= 0 else "S"
        lon_card = "E" if lon >= 0 else "W"

        return {
            "openstreetmap": f"https://www.openstreetmap.org/?mlat={lat_f}&mlon={lon_f}#map=16/{lat_f}/{lon_f}",
            "google_maps": f"https://www.google.com/maps?q={lat_f},{lon_f}",
            "apple_maps": f"https://maps.apple.com/?q={lat_f},{lon_f}",
            "bing_maps": f"https://www.bing.com/maps?cp={lat_f}~{lon_f}&lvl=16",
            "geohack": f"https://geohack.toolforge.org/geohack.php?params={abs(lat):.4f}_{lat_card}_{abs(lon):.4f}_{lon_card}",
        }

    @staticmethod
    def parse_datetime(date_str: Optional[str]) -> Optional[datetime]:
        """Parses common EXIF, ISO, and filesystem datetime strings into UTC datetime objects."""
        if not date_str or not isinstance(date_str, str):
            return None
        formats = [
            "%Y:%m:%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
            "%Y:%m:%d",
        ]
        clean_str = str(date_str).strip().split("+")[0].split(".")[0]
        for fmt in formats:
            try:
                dt = datetime.strptime(clean_str, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass
        return None

