"""
Optical Field-of-View (FOV), Camera Heading, and Horizon Ray-Casting Engine.

Calculates camera Horizontal/Vertical Field of View from lens focal length,
compass orientation (GPSImgDirection), and projects 2D/3D optical viewing cones.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class OpticalViewingCone:
    """Represents a camera's directional viewing frustum projected onto the earth's surface."""
    origin_lat: float
    origin_lon: float
    heading_deg: float  # Compass orientation (0 - 360)
    heading_ref: str  # 'T' (True North) or 'M' (Magnetic)
    focal_length_mm: Optional[float]
    focal_length_35mm: Optional[float]
    hfov_degrees: float
    vfov_degrees: float
    dfov_degrees: float
    viewing_distance_meters: float
    left_bearing_deg: float
    right_bearing_deg: float
    cone_polygon_coords: List[Tuple[float, float]]  # List of (lat, lon) defining the viewing sector

    def to_dict(self) -> Dict[str, Any]:
        return {
            "origin_lat": self.origin_lat,
            "origin_lon": self.origin_lon,
            "heading_deg": round(self.heading_deg, 2),
            "heading_ref": self.heading_ref,
            "focal_length_mm": self.focal_length_mm,
            "focal_length_35mm": self.focal_length_35mm,
            "hfov_degrees": round(self.hfov_degrees, 2),
            "vfov_degrees": round(self.vfov_degrees, 2),
            "dfov_degrees": round(self.dfov_degrees, 2),
            "viewing_distance_meters": round(self.viewing_distance_meters, 1),
            "left_bearing_deg": round(self.left_bearing_deg, 2),
            "right_bearing_deg": round(self.right_bearing_deg, 2),
            "polygon_latlngs": [
                [round(lat, 6), round(lon, 6)] for lat, lon in self.cone_polygon_coords
            ],
        }


class OpticalRayCaster:
    """
    Computes camera optical geometry and geodesic viewing cones.
    """

    # Standard full-frame 35mm sensor dimensions (36mm x 24mm, diagonal = 43.27mm)
    SENSOR_WIDTH_35MM = 36.0
    SENSOR_HEIGHT_35MM = 24.0
    SENSOR_DIAG_35MM = math.sqrt(36.0**2 + 24.0**2)  # ~43.267mm

    @classmethod
    def compute_fov_from_focal_length(
        cls,
        focal_length_35mm: Optional[float] = None,
        focal_length_mm: Optional[float] = None,
        sensor_width_mm: Optional[float] = None
    ) -> Tuple[float, float, float]:
        """
        Computes (HFOV, VFOV, DFOV) in degrees from 35mm equivalent focal length or physical focal length.
        Defaults to standard 50mm human perspective if focal length is unavailable.
        """
        # Determine effective 35mm focal length
        f_eff: float = 50.0  # Default normal lens (~40 deg HFOV)

        if focal_length_35mm and focal_length_35mm > 0:
            f_eff = float(focal_length_35mm)
        elif focal_length_mm and focal_length_mm > 0:
            if sensor_width_mm and sensor_width_mm > 0:
                # Calculate from physical sensor width
                crop_factor = cls.SENSOR_WIDTH_35MM / sensor_width_mm
                f_eff = float(focal_length_mm) * crop_factor
            else:
                # Assume standard smartphone crop factor ~5.6x if focal length < 10mm, else full-frame
                if focal_length_mm < 10.0:
                    f_eff = float(focal_length_mm) * 5.6  # Typical smartphone main camera (~24-28mm eq)
                else:
                    f_eff = float(focal_length_mm)

        f_eff = max(1.0, f_eff)  # Prevent division by zero

        # HFOV = 2 * arctan(width / (2 * f))
        hfov_rad = 2.0 * math.atan(cls.SENSOR_WIDTH_35MM / (2.0 * f_eff))
        vfov_rad = 2.0 * math.atan(cls.SENSOR_HEIGHT_35MM / (2.0 * f_eff))
        dfov_rad = 2.0 * math.atan(cls.SENSOR_DIAG_35MM / (2.0 * f_eff))

        return (
            math.degrees(hfov_rad),
            math.degrees(vfov_rad),
            math.degrees(dfov_rad),
        )

    @classmethod
    def destination_point(
        cls,
        lat: float,
        lon: float,
        bearing_deg: float,
        distance_meters: float
    ) -> Tuple[float, float]:
        """
        Computes the destination coordinate given an origin, bearing, and distance (WGS-84 great circle).
        """
        R = 6371008.8  # Earth mean radius in meters
        d_div_r = distance_meters / R
        brng_rad = math.radians(bearing_deg)
        lat_rad = math.radians(lat)
        lon_rad = math.radians(lon)

        dest_lat_rad = math.asin(
            math.sin(lat_rad) * math.cos(d_div_r) +
            math.cos(lat_rad) * math.sin(d_div_r) * math.cos(brng_rad)
        )
        dest_lon_rad = lon_rad + math.atan2(
            math.sin(brng_rad) * math.sin(d_div_r) * math.cos(lat_rad),
            math.cos(d_div_r) - math.sin(lat_rad) * math.sin(dest_lat_rad)
        )
        return (math.degrees(dest_lat_rad), math.degrees(dest_lon_rad))

    @classmethod
    def calculate_viewing_cone(
        cls,
        lat: float,
        lon: float,
        heading_deg: float,
        heading_ref: str = "T",
        focal_length_35mm: Optional[float] = None,
        focal_length_mm: Optional[float] = None,
        viewing_distance_meters: float = 300.0,
        num_arc_points: int = 16
    ) -> OpticalViewingCone:
        """
        Calculates the complete 2D optical viewing sector polygon for map projection.
        """
        hfov, vfov, dfov = cls.compute_fov_from_focal_length(
            focal_length_35mm=focal_length_35mm,
            focal_length_mm=focal_length_mm
        )

        half_hfov = hfov / 2.0
        left_bearing = (heading_deg - half_hfov) % 360.0
        right_bearing = (heading_deg + half_hfov) % 360.0

        # Build sector polygon: [Origin -> Left Arc ... Right Arc -> Origin]
        polygon: List[Tuple[float, float]] = [(lat, lon)]

        # Sample points along the arc from left to right bearing
        # Handle wrap-around
        span = hfov
        for i in range(num_arc_points + 1):
            fraction = i / float(num_arc_points)
            cur_bearing = (left_bearing + fraction * span) % 360.0
            pt = cls.destination_point(lat, lon, cur_bearing, viewing_distance_meters)
            polygon.append(pt)

        # Close polygon
        polygon.append((lat, lon))

        return OpticalViewingCone(
            origin_lat=lat,
            origin_lon=lon,
            heading_deg=heading_deg,
            heading_ref=heading_ref,
            focal_length_mm=focal_length_mm,
            focal_length_35mm=focal_length_35mm,
            hfov_degrees=hfov,
            vfov_degrees=vfov,
            dfov_degrees=dfov,
            viewing_distance_meters=viewing_distance_meters,
            left_bearing_deg=left_bearing,
            right_bearing_deg=right_bearing,
            cone_polygon_coords=polygon
        )
