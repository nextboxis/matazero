"""
Natural Earth Vector SQLite Query Engine.

Provides high-speed offline spatial querying, reverse geocoding, airport/seaport
facility proximity detection, and administrative hierarchy resolution using the
Natural Earth Vector SQLite database (ne_10m layers).
"""

from __future__ import annotations

import math
import os
import sqlite3
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SQLiteGeocodeResult:
    """Structured reverse geocode match from Natural Earth SQLite database."""
    name: str
    country: str
    country_code: str
    admin1: str
    lat: float
    lon: float
    distance_km: float
    timezone: str
    feature_type: str = "city"
    population: int = 0
    is_approximate: bool = False
    display_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "country": self.country,
            "country_code": self.country_code,
            "admin1": self.admin1,
            "lat": self.lat,
            "lon": self.lon,
            "distance_km": round(self.distance_km, 2),
            "timezone": self.timezone,
            "feature_type": self.feature_type,
            "population": self.population,
            "is_approximate": self.is_approximate,
            "display_name": self.display_name,
        }


@dataclass
class FacilityMatch:
    """Proximity match to an airport, seaport, or transit hub."""
    facility_type: str  # 'airport' | 'port'
    name: str
    code: str  # IATA/ICAO code or identifier
    category: str
    lat: float
    lon: float
    distance_km: float
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "facility_type": self.facility_type,
            "name": self.name,
            "code": self.code,
            "category": self.category,
            "lat": self.lat,
            "lon": self.lon,
            "distance_km": round(self.distance_km, 2),
            "details": self.details,
        }


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Compute great-circle distance between two WGS-84 points in kilometers."""
    R = 6371.0088
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (math.sin(delta_phi / 2.0) ** 2 +
         math.cos(phi1) * math.cos(phi2) * (math.sin(delta_lambda / 2.0) ** 2))
    a = min(1.0, max(0.0, a))
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return R * c


def decode_wkb_point(geom_bytes: Optional[bytes]) -> Tuple[Optional[float], Optional[float]]:
    """Decode OGC Well-Known Binary (WKB) 2D Point into (lat, lon)."""
    if not geom_bytes or len(geom_bytes) < 21:
        return None, None
    try:
        # Little-endian (byte 0 == 1)
        if geom_bytes[0] == 1 and geom_bytes[1:5] == b'\x01\x00\x00\x00':
            lon, lat = struct.unpack('<dd', geom_bytes[5:21])
            return lat, lon
        # Big-endian (byte 0 == 0)
        elif geom_bytes[0] == 0 and geom_bytes[1:5] == b'\x00\x00\x00\x01':
            lon, lat = struct.unpack('>dd', geom_bytes[5:21])
            return lat, lon
    except Exception:
        pass
    return None, None


class NaturalEarthDB:
    """
    High-speed spatial interface for Natural Earth Vector SQLite Database.
    """

    _instance: Optional[NaturalEarthDB] = None
    _db_path: Optional[str] = None

    DEFAULT_PATHS = [
        r"J:\PROGRAM\mata\sqlite\natural_earth_vector.sqlite\packages\natural_earth_vector.sqlite",
        r"J:\PROGRAM\mata\sqlite\natural_earth_vector.sqlite",
        "sqlite/natural_earth_vector.sqlite/packages/natural_earth_vector.sqlite",
        "sqlite/natural_earth_vector.sqlite",
    ]

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = self._resolve_db_path(db_path)
        self._conn: Optional[sqlite3.Connection] = None
        if self.db_path and os.path.exists(self.db_path):
            try:
                self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            except Exception:
                self._conn = None

    @classmethod
    def get_instance(cls, db_path: Optional[str] = None) -> NaturalEarthDB:
        """Get or initialize singleton instance of NaturalEarthDB."""
        if cls._instance is None or (db_path and db_path != cls._db_path):
            cls._instance = cls(db_path=db_path)
            cls._db_path = cls._instance.db_path
        return cls._instance

    @classmethod
    def _resolve_db_path(cls, custom_path: Optional[str] = None) -> Optional[str]:
        """Locate the Natural Earth SQLite database on disk."""
        if custom_path and os.path.exists(custom_path):
            return custom_path

        env_path = os.environ.get("NATURAL_EARTH_SQLITE")
        if env_path and os.path.exists(env_path):
            return env_path

        # Check default paths
        base_dir = Path(__file__).resolve().parents[4]  # repo root (j:\PROGRAM\mata)
        for rel in cls.DEFAULT_PATHS:
            p = Path(rel)
            if p.is_absolute() and p.exists():
                return str(p)
            candidate = base_dir / rel
            if candidate.exists():
                return str(candidate)

        return None

    @property
    def is_available(self) -> bool:
        """Check if SQLite database is loaded and connected."""
        return self._conn is not None

    def reverse_geocode(
        self,
        lat: float,
        lon: float,
        max_distance_km: float = 150.0
    ) -> Optional[SQLiteGeocodeResult]:
        """
        Find the nearest populated place / city from Natural Earth ne_10m_populated_places.
        Uses expanding spatial window queries with geodesic distance ranking.
        """
        if not self.is_available or self._conn is None:
            return None

        # Search windows (in degrees): 1.0 deg (~111km), 3.0 deg (~333km), 10.0 deg (~1110km)
        windows = [1.0, 3.0, 10.0, 45.0]
        cursor = self._conn.cursor()

        best_match: Optional[Tuple[str, str, str, str, float, float, str, int, str, float]] = None
        min_dist = float("inf")

        for win in windows:
            cursor.execute('''
                SELECT name, nameascii, adm0name, sov0name, adm1name, iso_a2, latitude, longitude, timezone, pop_max, featurecla
                FROM "ne_10m_populated_places"
                WHERE latitude BETWEEN ? AND ? AND longitude BETWEEN ? AND ?
            ''', (lat - win, lat + win, lon - win, lon + win))
            rows = cursor.fetchall()

            if rows:
                for r in rows:
                    name, nameascii, adm0name, sov0name, adm1name, iso_a2, p_lat, p_lon, tz, pop, fclass = r
                    if p_lat is None or p_lon is None:
                        continue
                    d = haversine_distance(lat, lon, p_lat, p_lon)
                    if d < min_dist:
                        min_dist = d
                        c_name = (nameascii or name or "").strip()
                        country = (adm0name or sov0name or "").strip()
                        admin1 = (adm1name or "").strip()
                        cc = (iso_a2 or "").strip().upper()
                        best_match = (c_name, country, cc, admin1, p_lat, p_lon, tz or "UTC", int(pop or 0), fclass or "city", min_dist)
                
                # If we found matches within this window and distance is reasonable, break early
                if min_dist <= max_distance_km:
                    break

        if not best_match:
            return None

        c_name, country, cc, admin1, p_lat, p_lon, tz, pop, fclass, d_km = best_match
        is_approx = d_km > max_distance_km

        if is_approx:
            display_name = f"Remote / Offshore Area (approx. {int(round(d_km))}km from {c_name})"
        else:
            parts = [c_name]
            if admin1 and admin1 != c_name:
                parts.append(admin1)
            if country:
                parts.append(country)
            display_name = ", ".join(parts)

        return SQLiteGeocodeResult(
            name=c_name,
            country=country,
            country_code=cc,
            admin1=admin1,
            lat=p_lat,
            lon=p_lon,
            distance_km=d_km,
            timezone=tz,
            feature_type=fclass,
            population=pop,
            is_approximate=is_approx,
            display_name=display_name,
        )

    def find_nearest_airport(
        self,
        lat: float,
        lon: float,
        max_distance_km: float = 60.0
    ) -> Optional[FacilityMatch]:
        """
        Find the nearest international or domestic airport from ne_10m_airports.
        """
        if not self.is_available or self._conn is None:
            return None

        cursor = self._conn.cursor()
        # Search radius window (~1.0 degree ~= 111 km)
        cursor.execute('''
            SELECT name, name_en, iata_code, gps_code, type, GEOMETRY
            FROM "ne_10m_airports"
        ''')
        rows = cursor.fetchall()

        best_match: Optional[FacilityMatch] = None
        min_dist = float("inf")

        for r in rows:
            name, name_en, iata, gps, ap_type, geom = r
            ap_lat, ap_lon = decode_wkb_point(geom)
            if ap_lat is None or ap_lon is None:
                continue

            d = haversine_distance(lat, lon, ap_lat, ap_lon)
            if d < min_dist:
                min_dist = d
                ap_name = (name_en or name or "").strip()
                code = iata if (iata and iata != "-99") else (gps if (gps and gps != "-99") else "")
                
                clean_ap_name = ap_name if ap_name.lower().endswith("airport") else f"{ap_name} Airport"
                code_str = f" [{code}]" if code else ""
                details = f"{d:.1f}km from {clean_ap_name}{code_str} ({ap_type})"

                best_match = FacilityMatch(
                    facility_type="airport",
                    name=clean_ap_name,
                    code=code,
                    category=ap_type or "airport",
                    lat=ap_lat,
                    lon=ap_lon,
                    distance_km=d,
                    details=details,
                )

        if best_match and best_match.distance_km <= max_distance_km:
            return best_match
        return None

    def find_nearest_port(
        self,
        lat: float,
        lon: float,
        max_distance_km: float = 40.0
    ) -> Optional[FacilityMatch]:
        """
        Find the nearest seaport or maritime facility from ne_10m_ports.
        """
        if not self.is_available or self._conn is None:
            return None

        cursor = self._conn.cursor()
        cursor.execute('''
            SELECT name, featurecla, website, GEOMETRY
            FROM "ne_10m_ports"
        ''')
        rows = cursor.fetchall()

        best_match: Optional[FacilityMatch] = None
        min_dist = float("inf")

        for r in rows:
            name, fclass, web, geom = r
            p_lat, p_lon = decode_wkb_point(geom)
            if p_lat is None or p_lon is None:
                continue

            d = haversine_distance(lat, lon, p_lat, p_lon)
            if d < min_dist:
                min_dist = d
                p_name = (name or "").strip()
                clean_port_name = p_name if p_name.lower().startswith("port") else f"Port of {p_name}"
                details = f"{d:.1f}km from {clean_port_name}"

                best_match = FacilityMatch(
                    facility_type="port",
                    name=clean_port_name,
                    code="",
                    category=fclass or "seaport",
                    lat=p_lat,
                    lon=p_lon,
                    distance_km=d,
                    details=details,
                )

        if best_match and best_match.distance_km <= max_distance_km:
            return best_match
        return None

    def get_facility_context(
        self,
        lat: float,
        lon: float,
        airport_max_km: float = 50.0,
        port_max_km: float = 30.0
    ) -> Dict[str, Any]:
        """
        Retrieve combined proximity intelligence for aviation and maritime facilities.
        """
        result: Dict[str, Any] = {
            "has_facility_proximity": False,
            "facilities": [],
            "summary": "No major aviation or maritime transit hub within immediate proximity.",
        }

        airport = self.find_nearest_airport(lat, lon, max_distance_km=airport_max_km)
        port = self.find_nearest_port(lat, lon, max_distance_km=port_max_km)

        summaries = []
        if airport:
            result["facilities"].append(airport.to_dict())
            summaries.append(airport.details)
        if port:
            result["facilities"].append(port.to_dict())
            summaries.append(port.details)

        if summaries:
            result["has_facility_proximity"] = True
            result["summary"] = "; ".join(summaries)

        return result
