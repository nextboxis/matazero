"""Forensic-grade Geolocation Intelligence and Chronolocation Engine.

Supports offline spatial KD-Tree lookups, timezone resolution via TimezoneFinder,
geodesic distance/bearing calculation via Geopy, and astronomical solar chronolocation via Astral/NOAA.

Includes coordinate sanitization, Null Island detection, distance-capped reverse geocoding,
kinematic speed analysis, and structured location confidence scoring.
"""

from __future__ import annotations
import json
import math
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# IANA timezone offset resolution (Python 3.9+ zoneinfo with pytz fallback)
try:
    from zoneinfo import ZoneInfo, available_timezones as _available_tz
    _HAS_ZONEINFO = True
except ImportError:
    try:
        from backports.zoneinfo import ZoneInfo, available_timezones as _available_tz
        _HAS_ZONEINFO = True
    except ImportError:
        _HAS_ZONEINFO = False

try:
    import pytz
    _HAS_PYTZ = True
except ImportError:
    _HAS_PYTZ = False

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

from .sqlite_engine import NaturalEarthDB, FacilityMatch, SQLiteGeocodeResult


COMPASS_DIRECTIONS = [
    "N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE",
    "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"
]


# --- Coordinate Validation Status Constants ---
COORD_VALID = "VALID"
COORD_NULL_ISLAND = "NULL_ISLAND"
COORD_OUT_OF_BOUNDS = "OUT_OF_BOUNDS"

# --- Location Confidence Levels ---
LOC_CONFIDENCE_HIGH = "HIGH"
LOC_CONFIDENCE_MEDIUM = "MEDIUM"
LOC_CONFIDENCE_LOW = "LOW"
LOC_CONFIDENCE_REJECTED = "REJECTED"


def _latlon_to_cartesian(lat: float, lon: float) -> Tuple[float, float, float]:
    """Converts (lat, lon) degrees to 3D Cartesian coordinates (x, y, z) on a unit sphere."""
    lat_r = math.radians(lat)
    lon_r = math.radians(lon)
    return (
        math.cos(lat_r) * math.cos(lon_r),
        math.cos(lat_r) * math.sin(lon_r),
        math.sin(lat_r)
    )


class _KDNode:
    __slots__ = ('point', 'data', 'axis', 'left', 'right')

    def __init__(self, point: Tuple[float, float, float], data: Dict[str, Any], axis: int, left=None, right=None):
        self.point = point
        self.data = data
        self.axis = axis
        self.left = left
        self.right = right


class SpatialKDTree:
    """3D Cartesian Spatial KD-Tree for sub-millisecond nearest neighbor search on spherical coordinates."""

    def __init__(self, places: List[Dict[str, Any]]):
        points: List[Tuple[Tuple[float, float, float], Dict[str, Any]]] = []
        for p in places:
            lat = p.get('lat')
            lon = p.get('lon')
            if lat is not None and lon is not None:
                cart = _latlon_to_cartesian(float(lat), float(lon))
                points.append((cart, p))
        self.root = self._build(points, depth=0)
        self.count = len(points)

    def _build(self, points: List[Tuple[Tuple[float, float, float], Dict[str, Any]]], depth: int) -> Optional[_KDNode]:
        if not points:
            return None
        axis = depth % 3
        points.sort(key=lambda item: item[0][axis])
        mid = len(points) // 2
        return _KDNode(
            point=points[mid][0],
            data=points[mid][1],
            axis=axis,
            left=self._build(points[:mid], depth + 1),
            right=self._build(points[mid + 1:], depth + 1)
        )

    def nearest(self, lat: float, lon: float) -> Optional[Dict[str, Any]]:
        """Find the nearest place in O(log N) time."""
        if not self.root:
            return None
        target = _latlon_to_cartesian(lat, lon)
        best = [None, float('inf')]

        def _search(node: Optional[_KDNode]):
            if node is None:
                return
            dx = node.point[0] - target[0]
            dy = node.point[1] - target[1]
            dz = node.point[2] - target[2]
            dist_sq = dx * dx + dy * dy + dz * dz

            if dist_sq < best[1]:
                best[0] = node.data
                best[1] = dist_sq

            axis = node.axis
            diff = target[axis] - node.point[axis]

            first = node.left if diff < 0 else node.right
            second = node.right if diff < 0 else node.left

            _search(first)
            if diff * diff < best[1]:
                _search(second)

        _search(self.root)
        return best[0]


class GeoLocator:
    """Unified Geolocation, Reverse Geocoding, and Solar Chronolocation Service."""

    _cached_places: Optional[List[Dict[str, Any]]] = None
    _spatial_tree: Optional[SpatialKDTree] = None

    @classmethod
    def load_offline_database(cls) -> List[Dict[str, Any]]:
        """Loads and caches the bundled offline GeoNames dataset and builds SpatialKDTree index."""
        if cls._cached_places is not None:
            return cls._cached_places

        data_file = Path(__file__).parent.parent / "data" / "geonames_offline.json"
        if not data_file.exists():
            cls._cached_places = []
            cls._spatial_tree = SpatialKDTree([])
            return cls._cached_places

        try:
            with open(data_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                cls._cached_places = data.get("places", [])
                cls._spatial_tree = SpatialKDTree(cls._cached_places)
        except Exception:
            cls._cached_places = []
            cls._spatial_tree = SpatialKDTree([])
        return cls._cached_places

    # -------------------------------------------------------------------------
    # Idea 1: Coordinate Sanitization & Null Island Detection
    # -------------------------------------------------------------------------

    @staticmethod
    def validate_coordinates(lat: float, lon: float) -> Dict[str, Any]:
        """Validates GPS coordinates for bounds and Null Island (0,0) anomaly.

        Returns a dict with:
          - status: COORD_VALID | COORD_NULL_ISLAND | COORD_OUT_OF_BOUNDS
          - reason: Human-readable explanation
          - is_valid: Boolean shorthand
        """
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            return {
                "status": COORD_OUT_OF_BOUNDS,
                "reason": f"Non-numeric coordinate values: lat={lat!r}, lon={lon!r}",
                "is_valid": False,
            }

        if math.isnan(lat) or math.isnan(lon) or math.isinf(lat) or math.isinf(lon):
            return {
                "status": COORD_OUT_OF_BOUNDS,
                "reason": f"NaN or Inf coordinate values: lat={lat}, lon={lon}",
                "is_valid": False,
            }

        if not (-90.0 <= lat <= 90.0) or not (-180.0 <= lon <= 180.0):
            return {
                "status": COORD_OUT_OF_BOUNDS,
                "reason": f"Coordinates outside WGS-84 bounds: lat={lat}, lon={lon} (valid: -90..90, -180..180)",
                "is_valid": False,
            }

        if abs(lat) < 0.0001 and abs(lon) < 0.0001:
            return {
                "status": COORD_NULL_ISLAND,
                "reason": (
                    "Coordinates at (0.0, 0.0) — 'Null Island' in the Gulf of Guinea. "
                    "This almost always indicates an uninitialized GPS fix, failed satellite lock, "
                    "or metadata zeroing by a privacy/stripping tool."
                ),
                "is_valid": False,
            }

        return {
            "status": COORD_VALID,
            "reason": "Coordinates within valid WGS-84 bounds.",
            "is_valid": True,
        }

    @staticmethod
    def is_null_island(lat: float, lon: float) -> bool:
        """Quick check: are coordinates at Null Island (0°N, 0°E)?"""
        try:
            return abs(float(lat)) < 0.0001 and abs(float(lon)) < 0.0001
        except (TypeError, ValueError):
            return False

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
    def reverse_geocode_offline(
        cls, lat: float, lon: float, max_distance_km: float = 150.0
    ) -> Optional[Dict[str, Any]]:
        """Performs nearest-neighbor offline reverse geocoding against bundled database or Natural Earth SQLite.

        Args:
            lat: Latitude in decimal degrees.
            lon: Longitude in decimal degrees.
            max_distance_km: Maximum distance threshold. If the nearest city is
                further than this, the result is marked as approximate/remote.

        Returns:
            Dict with geocoding result, or None if database is empty.
            Includes 'is_approximate' flag when distance exceeds threshold.
        """
        # Reject Null Island and out-of-bounds coordinates
        validation = cls.validate_coordinates(lat, lon)
        if not validation["is_valid"]:
            return None

        # 1. Try direct Natural Earth Vector SQLite database if available
        ne_db = NaturalEarthDB.get_instance()
        if ne_db.is_available:
            try:
                sq_res = ne_db.reverse_geocode(lat, lon, max_distance_km=max_distance_km)
                if sq_res:
                    res_dict: Dict[str, Any] = {
                        "closest_city": sq_res.name,
                        "admin_region": sq_res.admin1,
                        "country": sq_res.country,
                        "country_code": sq_res.country_code,
                        "timezone": sq_res.timezone or cls.get_timezone(lat, lon),
                        "approx_distance_km": round(sq_res.distance_km, 2),
                        "approx_distance_miles": round(sq_res.distance_km * 0.621371, 2),
                        "is_approximate": sq_res.is_approximate,
                        "feature_type": sq_res.feature_type,
                        "population": sq_res.population,
                    }
                    if sq_res.is_approximate:
                        res_dict["location_label"] = sq_res.display_name
                    return res_dict
            except Exception:
                pass

        # 2. Fall back to bundled offline JSON database (11,000+ places indexed via SpatialKDTree)
        places = cls.load_offline_database()
        if not places or not cls._spatial_tree:
            return None

        best_place = cls._spatial_tree.nearest(lat, lon)
        if not best_place:
            return None

        plat = best_place.get("lat")
        plon = best_place.get("lon")
        if plat is None or plon is None:
            return None

        min_dist_km = cls.compute_haversine_distance(lat, lon, float(plat), float(plon))

        if best_place:
            tz = best_place.get("timezone") or cls.get_timezone(lat, lon)
            is_approximate = min_dist_km > max_distance_km

            result: Dict[str, Any] = {
                "closest_city": best_place.get("name"),
                "admin_region": best_place.get("admin1"),
                "country": best_place.get("country"),
                "country_code": best_place.get("country_code", ""),
                "timezone": tz,
                "approx_distance_km": round(min_dist_km, 2),
                "approx_distance_miles": round(min_dist_km * 0.621371, 2),
                "is_approximate": is_approximate,
            }

            if is_approximate:
                result["location_label"] = (
                    f"Remote / Offshore Area (approx. {round(min_dist_km)}km from {best_place.get('name')})"
                )

            return result
        return None

    @classmethod
    def get_facility_context(
        cls, lat: float, lon: float, airport_max_km: float = 50.0, port_max_km: float = 30.0
    ) -> Dict[str, Any]:
        """Retrieves airport and seaport facility proximity context for given coordinates."""
        validation = cls.validate_coordinates(lat, lon)
        if not validation["is_valid"]:
            return {
                "has_facility_proximity": False,
                "facilities": [],
                "summary": "Coordinates invalid or uninitialized.",
            }

        ne_db = NaturalEarthDB.get_instance()
        if ne_db.is_available:
            try:
                return ne_db.get_facility_context(
                    lat, lon, airport_max_km=airport_max_km, port_max_km=port_max_km
                )
            except Exception:
                pass

        return {
            "has_facility_proximity": False,
            "facilities": [],
            "summary": "Natural Earth database not connected.",
        }


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

    # -------------------------------------------------------------------------
    # Idea 4: IANA Timezone Offset Validation (replaces lon / 15.0 heuristic)
    # -------------------------------------------------------------------------

    @classmethod
    def get_valid_utc_offsets_for_zone(cls, iana_zone: str) -> List[float]:
        """Returns all historically valid UTC offsets (in hours) for an IANA timezone,
        including both standard and daylight saving time variants.

        This replaces the naive lon/15.0 heuristic that false-flagged countries like
        China (single UTC+8 zone across 60° longitude) and western Spain (UTC+1 at negative longitude).
        """
        offsets: set = set()

        # Strategy 1: Use zoneinfo (Python 3.9+)
        if _HAS_ZONEINFO:
            try:
                tz = ZoneInfo(iana_zone)
                # Sample the last 2 years at monthly intervals to catch DST transitions
                base = datetime(2024, 1, 1, 12, 0, 0)
                for month_offset in range(24):
                    dt = base.replace(month=((month_offset % 12) + 1), year=2024 + month_offset // 12)
                    dt_aware = dt.replace(tzinfo=tz)
                    off_hours = dt_aware.utcoffset().total_seconds() / 3600.0
                    offsets.add(round(off_hours, 2))
                return sorted(offsets)
            except Exception:
                pass

        # Strategy 2: Use pytz
        if _HAS_PYTZ:
            try:
                tz = pytz.timezone(iana_zone)
                # pytz stores _utc_transition_times for historical offsets
                if hasattr(tz, '_utc_transition_times') and tz._utc_transition_times:
                    for trans_info in tz._transition_info[-24:]:
                        off_hours = trans_info[0].total_seconds() / 3600.0
                        offsets.add(round(off_hours, 2))
                else:
                    # Fixed-offset zone
                    dt = datetime(2024, 6, 15, 12, 0, 0)
                    dt_aware = tz.localize(dt)
                    off_hours = dt_aware.utcoffset().total_seconds() / 3600.0
                    offsets.add(round(off_hours, 2))
                if offsets:
                    return sorted(offsets)
            except Exception:
                pass

        # Strategy 3: Fallback — cannot validate, return empty (caller should skip check)
        return []

    @classmethod
    def is_offset_valid_for_zone(cls, iana_zone: str, claimed_offset_hours: float) -> bool:
        """Returns True if the claimed UTC offset (in hours) is a valid offset
        for the given IANA timezone (including DST variants).

        Returns True (permissive) if timezone data is unavailable.
        """
        valid_offsets = cls.get_valid_utc_offsets_for_zone(iana_zone)
        if not valid_offsets:
            # Cannot validate — be permissive to avoid false positives
            return True

        # Allow 0.5 hour tolerance for half-hour zones (e.g., India UTC+5:30)
        for valid_off in valid_offsets:
            if abs(claimed_offset_hours - valid_off) < 0.6:
                return True
        return False

    # -------------------------------------------------------------------------
    # Idea 3: Timezone-Aware Capture UTC Resolution
    # -------------------------------------------------------------------------

    @classmethod
    def resolve_capture_utc(
        cls, date_str: str, lat: float, lon: float, offset_str: Optional[str] = None
    ) -> Optional[datetime]:
        """Resolves a capture datetime string to true UTC using IANA timezone lookup.

        When OffsetTimeOriginal is present, uses it directly.
        When absent, resolves the IANA timezone from GPS coordinates and localizes
        the camera local time into that timezone before converting to UTC.

        This fixes false solar chronolocation errors where local camera time was
        incorrectly treated as UTC.
        """
        dt_naive = cls.parse_datetime(date_str)
        if dt_naive is None:
            return None

        # Strip any assumed UTC timezone for re-localization
        dt_naive = dt_naive.replace(tzinfo=None)

        # 1. If explicit offset is provided, use it directly
        if offset_str and ":" in str(offset_str):
            try:
                sign = -1 if str(offset_str).startswith("-") else 1
                parts = str(offset_str).lstrip("+-").split(":")
                hrs = int(parts[0])
                mins = int(parts[1]) if len(parts) > 1 else 0
                tz_offset = timezone(sign * timedelta(hours=hrs, minutes=mins))
                dt_aware = dt_naive.replace(tzinfo=tz_offset)
                return dt_aware.astimezone(timezone.utc)
            except Exception:
                pass

        # 2. Resolve IANA timezone from GPS coordinates
        iana_zone = cls.get_timezone(lat, lon)
        if iana_zone:
            # Try zoneinfo first
            if _HAS_ZONEINFO:
                try:
                    tz = ZoneInfo(iana_zone)
                    dt_aware = dt_naive.replace(tzinfo=tz)
                    return dt_aware.astimezone(timezone.utc)
                except Exception:
                    pass

            # Try pytz
            if _HAS_PYTZ:
                try:
                    tz = pytz.timezone(iana_zone)
                    dt_aware = tz.localize(dt_naive)
                    return dt_aware.astimezone(timezone.utc).replace(tzinfo=timezone.utc)
                except Exception:
                    pass

        # 3. Fallback: treat as UTC (current behavior, preserves backward compat)
        return dt_naive.replace(tzinfo=timezone.utc)

    # -------------------------------------------------------------------------
    # Idea 5: Kinematic Speed Calculation
    # -------------------------------------------------------------------------

    @classmethod
    def compute_kinematic_speed(
        cls,
        lat1: float, lon1: float, dt1: datetime,
        lat2: float, lon2: float, dt2: datetime,
    ) -> Optional[Dict[str, Any]]:
        """Computes implied travel speed between two geolocated and timestamped points.

        Returns:
            Dict with distance_km, time_delta_seconds, speed_kmh, is_anomalous.
            Returns None if timestamps are identical or coordinates are invalid.
        """
        # Validate both coordinate pairs
        if cls.is_null_island(lat1, lon1) or cls.is_null_island(lat2, lon2):
            return None

        v1 = cls.validate_coordinates(lat1, lon1)
        v2 = cls.validate_coordinates(lat2, lon2)
        if not v1["is_valid"] or not v2["is_valid"]:
            return None

        distance_km = cls.compute_haversine_distance(lat1, lon1, lat2, lon2)

        # Ensure both datetimes are timezone-aware for comparison
        if dt1.tzinfo is None:
            dt1 = dt1.replace(tzinfo=timezone.utc)
        if dt2.tzinfo is None:
            dt2 = dt2.replace(tzinfo=timezone.utc)

        time_delta_sec = abs((dt2 - dt1).total_seconds())
        if time_delta_sec < 1.0:
            return None  # Cannot compute speed with zero time delta

        speed_kmh = (distance_km / time_delta_sec) * 3600.0

        # Threshold: > 1000 km/h is physically implausible without aviation
        is_anomalous = speed_kmh > 1000.0

        return {
            "distance_km": round(distance_km, 3),
            "time_delta_seconds": round(time_delta_sec, 1),
            "speed_kmh": round(speed_kmh, 1),
            "is_anomalous": is_anomalous,
            "anomaly_reason": (
                f"Implied travel speed of {round(speed_kmh, 1)} km/h exceeds physical plausibility "
                f"threshold (1000 km/h). Possible GPS spoofing, metadata splicing, or coordinate injection."
            ) if is_anomalous else None,
        }

    # -------------------------------------------------------------------------
    # Idea 6: Location Confidence Scoring
    # -------------------------------------------------------------------------

    @classmethod
    def compute_location_confidence(
        cls,
        lat: float,
        lon: float,
        dop: Optional[float] = None,
        has_gps_timestamp: bool = False,
        solar_elevation: Optional[float] = None,
        day_phase: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Computes a structured confidence rating for a GPS fix.

        Levels:
          HIGH: Valid coords + GPS satellite time + DOP < 5.0 + sun elevation consistent.
          MEDIUM: Valid coords + reverse geocode match, but missing satellite verification.
          LOW: Valid coords but significant quality issues (high DOP, solar mismatch).
          REJECTED: Null Island, out-of-bounds, or severe contradictions.
        """
        validation = cls.validate_coordinates(lat, lon)

        if not validation["is_valid"]:
            return {
                "level": LOC_CONFIDENCE_REJECTED,
                "score": 0.0,
                "signals": {
                    "coordinate_status": validation["status"],
                    "reason": validation["reason"],
                },
            }

        score = 0.5  # Base score for valid coordinates
        signals: Dict[str, Any] = {
            "coordinate_status": COORD_VALID,
        }

        # GPS satellite time verification
        if has_gps_timestamp:
            score += 0.2
            signals["gps_satellite_time"] = "present"
        else:
            signals["gps_satellite_time"] = "absent"

        # Dilution of Precision
        if dop is not None:
            signals["gps_dop"] = dop
            if dop < 2.0:
                score += 0.15
                signals["dop_quality"] = "excellent"
            elif dop < 5.0:
                score += 0.1
                signals["dop_quality"] = "good"
            elif dop < 10.0:
                score += 0.0
                signals["dop_quality"] = "moderate"
            else:
                score -= 0.1
                signals["dop_quality"] = "poor"

        # Solar consistency check
        if solar_elevation is not None and day_phase is not None:
            sun_visible = solar_elevation > 0.0
            daylight_phase = day_phase in ("Daylight", "Golden Hour")
            if sun_visible == daylight_phase:
                score += 0.1
                signals["solar_consistency"] = "consistent"
            else:
                score -= 0.15
                signals["solar_consistency"] = "inconsistent"

        # Determine level
        score = max(0.0, min(1.0, score))
        if score >= 0.8:
            level = LOC_CONFIDENCE_HIGH
        elif score >= 0.5:
            level = LOC_CONFIDENCE_MEDIUM
        else:
            level = LOC_CONFIDENCE_LOW

        return {
            "level": level,
            "score": round(score, 2),
            "signals": signals,
        }

    # -------------------------------------------------------------------------
    # Idea 7: GeoJSON Spatial Boundary & Geofence Intelligence
    # -------------------------------------------------------------------------

    @classmethod
    def load_geojson_features(cls, geojson_input: str | Path | Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parses and standardizes features from a GeoJSON file, string, or dict."""
        data: Dict[str, Any]
        if isinstance(geojson_input, (str, Path)):
            p = Path(geojson_input)
            if p.is_file():
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                data = json.loads(str(geojson_input))
        elif isinstance(geojson_input, dict):
            data = geojson_input
        else:
            return []

        features: List[Dict[str, Any]] = []
        if data.get("type") == "FeatureCollection":
            features = data.get("features", [])
        elif data.get("type") == "Feature":
            features = [data]
        elif "geometry" in data:
            features = [{"type": "Feature", "properties": {}, "geometry": data}]
        return features

    @staticmethod
    def point_in_polygon(lon: float, lat: float, ring: List[List[float]]) -> bool:
        """Ray-casting algorithm for testing if a point (lon, lat) is inside a polygon ring."""
        n = len(ring)
        if n < 3:
            return False

        inside = False
        p1x, p1y = ring[0][0], ring[0][1]

        for i in range(1, n + 1):
            p2x, p2y = ring[i % n][0], ring[i % n][1]
            if lat > min(p1y, p2y):
                if lat <= max(p1y, p2y):
                    if lon <= max(p1x, p2x):
                        if p1y != p2y:
                            xinters = (lat - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                        else:
                            xinters = p1x
                        if p1x == p2x or lon <= xinters:
                            inside = not inside
            p1x, p1y = p2x, p2y

        return inside

    @classmethod
    def is_point_in_geofence(
        cls, lat: float, lon: float, geojson_input: str | Path | Dict[str, Any]
    ) -> Dict[str, Any]:
        """Tests whether coordinates (lat, lon) lie within any polygon inside a GeoJSON boundary.

        Returns:
            Dict with:
              - inside_geofence: bool
              - matched_feature_name: Optional[str]
              - matched_feature_properties: Dict
              - total_boundaries_checked: int
        """
        # Validate coordinates first
        validation = cls.validate_coordinates(lat, lon)
        if not validation["is_valid"]:
            return {
                "inside_geofence": False,
                "reason": f"Invalid coordinates: {validation['status']}",
                "matched_feature_name": None,
                "matched_feature_properties": {},
                "total_boundaries_checked": 0,
            }

        features = cls.load_geojson_features(geojson_input)
        if not features:
            return {
                "inside_geofence": False,
                "reason": "No valid features found in GeoJSON input",
                "matched_feature_name": None,
                "matched_feature_properties": {},
                "total_boundaries_checked": 0,
            }

        checked_count = 0
        for feat in features:
            geom = feat.get("geometry", {})
            g_type = geom.get("type", "")
            coords = geom.get("coordinates", [])
            props = feat.get("properties", {})
            feat_name = props.get("name") or props.get("title") or f"Feature_{checked_count + 1}"

            if g_type == "Polygon":
                checked_count += 1
                if coords and len(coords) > 0:
                    outer_ring = coords[0]
                    if cls.point_in_polygon(lon, lat, outer_ring):
                        # Check holes (inner rings)
                        in_hole = False
                        for hole in coords[1:]:
                            if cls.point_in_polygon(lon, lat, hole):
                                in_hole = True
                                break
                        if not in_hole:
                            return {
                                "inside_geofence": True,
                                "matched_feature_name": feat_name,
                                "matched_feature_properties": props,
                                "total_boundaries_checked": checked_count,
                            }

            elif g_type == "MultiPolygon":
                checked_count += 1
                for poly in coords:
                    if poly and len(poly) > 0:
                        outer_ring = poly[0]
                        if cls.point_in_polygon(lon, lat, outer_ring):
                            in_hole = False
                            for hole in poly[1:]:
                                if cls.point_in_polygon(lon, lat, hole):
                                    in_hole = True
                                    break
                            if not in_hole:
                                return {
                                    "inside_geofence": True,
                                    "matched_feature_name": feat_name,
                                    "matched_feature_properties": props,
                                    "total_boundaries_checked": checked_count,
                                }

        return {
            "inside_geofence": False,
            "matched_feature_name": None,
            "matched_feature_properties": {},
            "total_boundaries_checked": checked_count,
        }

    # -------------------------------------------------------------------------
    # Idea 8: IP Geolocation Ingestion & GPS-to-IP Spatial Correlation
    # -------------------------------------------------------------------------

    @classmethod
    def parse_ip_geolocation(cls, ip_data: Dict[str, Any] | str | Path) -> Optional[Dict[str, Any]]:
        """Parses and standardizes IP intelligence payloads (e.g. from ip-api.com, MaxMind, or GeoIP2).

        Supports formats like:
        {
          "query": "24.48.0.1",
          "status": "success",
          "country": "Canada",
          "countryCode": "CA",
          "region": "QC",
          "regionName": "Quebec",
          "city": "Montreal",
          "zip": "H1K",
          "lat": 45.6085,
          "lon": -73.5493,
          "timezone": "America/Toronto",
          "isp": "Le Groupe Videotron Ltee",
          "org": "Videotron Ltee",
          "as": "AS5769 Videotron Ltee"
        }
        """
        raw: Dict[str, Any]
        if isinstance(ip_data, (str, Path)):
            p = Path(ip_data)
            if p.is_file():
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        raw = json.load(f)
                except Exception:
                    return None
            else:
                try:
                    raw = json.loads(str(ip_data))
                except Exception:
                    return None
        elif isinstance(ip_data, dict):
            raw = ip_data
        else:
            return None

        if not raw:
            return None

        # Check status if ip-api.com format
        if raw.get("status") == "fail":
            return None

        lat = raw.get("lat") or raw.get("latitude")
        lon = raw.get("lon") or raw.get("longitude")
        if lat is None or lon is None:
            return None

        try:
            lat = float(lat)
            lon = float(lon)
        except (ValueError, TypeError):
            return None

        # Validate coordinates
        val = cls.validate_coordinates(lat, lon)
        if not val["is_valid"]:
            return None

        return {
            "ip": raw.get("query") or raw.get("ip") or "Unknown",
            "country": raw.get("country"),
            "country_code": (raw.get("countryCode") or raw.get("country_code") or "").upper(),
            "region": raw.get("region"),
            "region_name": raw.get("regionName") or raw.get("region_name"),
            "city": raw.get("city"),
            "postal_code": raw.get("zip") or raw.get("postal_code") or raw.get("postcode"),
            "latitude": round(lat, 6),
            "longitude": round(lon, 6),
            "timezone": raw.get("timezone") or cls.get_timezone(lat, lon),
            "isp": raw.get("isp"),
            "organization": raw.get("org") or raw.get("organization"),
            "autonomous_system": raw.get("as") or raw.get("asn"),
        }

    @classmethod
    def correlate_gps_with_ip(
        cls,
        gps_lat: float,
        gps_lon: float,
        ip_data: Dict[str, Any] | str | Path,
    ) -> Optional[Dict[str, Any]]:
        """Correlates an image's EXIF GPS fix with an IP Geolocation record to detect proxy/VPN anomalies or corroborate location.

        Returns:
            Dict containing:
              - ip_info: Standardized IP geolocation info
              - distance_km: Geodesic distance between EXIF GPS and IP location
              - distance_miles: Distance in miles
              - bearing: Bearing direction from IP location to GPS fix
              - correlation_verdict: "CORROBORATED_METRO" | "REGIONAL_PROXIMITY" | "NATIONAL_PROXIMITY" | "DISCREPANCY_ANOMALY"
              - timezone_match: Boolean indicating if IANA timezones match
              - is_suspicious: Boolean indicating large spatial divergence (>1000 km)
              - explanation: Forensic summary of the correlation
        """
        ip_info = cls.parse_ip_geolocation(ip_data)
        if not ip_info:
            return None

        v_gps = cls.validate_coordinates(gps_lat, gps_lon)
        if not v_gps["is_valid"]:
            return None

        ip_lat = ip_info["latitude"]
        ip_lon = ip_info["longitude"]

        dist_res = cls.compute_distance(ip_lat, ip_lon, gps_lat, gps_lon)
        dist_km = dist_res["distance_km"]
        dist_miles = dist_res["distance_miles"]
        bearing_res = cls.compute_bearing(ip_lat, ip_lon, gps_lat, gps_lon)

        # Timezone comparison
        gps_tz = cls.get_timezone(gps_lat, gps_lon)
        ip_tz = ip_info.get("timezone")
        tz_match = bool(gps_tz and ip_tz and gps_tz.lower() == ip_tz.lower())

        # Determine correlation verdict
        if dist_km <= 60.0:
            verdict = "CORROBORATED_METRO"
            is_suspicious = False
            explanation = (
                f"EXIF GPS fix is within {dist_km:.1f} km of IP location ({ip_info.get('city')}, {ip_info.get('country')}). "
                f"Strong spatial corroboration with ISP {ip_info.get('isp', 'network')}."
            )
        elif dist_km <= 300.0:
            verdict = "REGIONAL_PROXIMITY"
            is_suspicious = False
            explanation = (
                f"EXIF GPS fix is within {dist_km:.1f} km of IP location. "
                f"Consistent with regional mobile cellular or residential ISP routing ({ip_info.get('region_name')}, {ip_info.get('country')})."
            )
        elif dist_km <= 1200.0:
            verdict = "NATIONAL_PROXIMITY"
            is_suspicious = False
            explanation = (
                f"EXIF GPS fix is {dist_km:.1f} km from IP location within same general country/region. "
                f"Consistent with national backbone ISP or data center transit."
            )
        else:
            verdict = "DISCREPANCY_ANOMALY"
            is_suspicious = True
            explanation = (
                f"Severe spatial divergence ({dist_km:,.1f} km / {dist_miles:,.1f} mi) between claimed EXIF GPS "
                f"and uploader/network IP ({ip_info.get('city')}, {ip_info.get('country')}). "
                f"Indicates VPN/proxy exit node, Tor relay, cloud scraping, or spoofed EXIF GPS tags."
            )

        return {
            "ip_info": ip_info,
            "distance_km": dist_km,
            "distance_miles": dist_miles,
            "bearing_degrees": bearing_res["bearing_degrees"],
            "cardinal_direction": bearing_res["cardinal_direction"],
            "timezone_match": tz_match,
            "gps_timezone": gps_tz,
            "ip_timezone": ip_tz,
            "correlation_verdict": verdict,
            "is_suspicious": is_suspicious,
            "explanation": explanation,
        }

    @classmethod
    def resolve_ip_online(cls, ip_address: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
        """Resolves IP address to geolocation intelligence via public API (subject to GR-4.1 network governance)."""
        import urllib.request
        clean_ip = str(ip_address).strip()
        url = f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "matazero_forensic_geolocator/2.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    payload = json.loads(resp.read().decode("utf-8"))
                    return cls.parse_ip_geolocation(payload)
        except Exception:
            pass
        return None


