"""
NDJSON & GeoJSON Lines Streaming Ingestion Engine.

Enables high-throughput streaming ingestion of OpenStreetMap, Overture Maps,
and regional hamlet/village datasets (such as place-hamlet.ndjson, place-village.ndjson).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set, Tuple


class NDJSONGeoIngester:
    """
    Streaming parser and merger for geospatial NDJSON datasets.
    """

    @staticmethod
    def parse_line(line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single NDJSON line into a standardized place dictionary.
        Supports standard GeoJSON Feature format, Overture Maps format, and flat JSON.
        """
        line = line.strip()
        if not line:
            return None

        try:
            obj = json.loads(line)
        except Exception:
            return None

        # 1. GeoJSON Feature format
        if obj.get("type") == "Feature" or "geometry" in obj:
            geom = obj.get("geometry") or {}
            coords = geom.get("coordinates")
            if not coords or len(coords) < 2:
                return None
            lon, lat = float(coords[0]), float(coords[1])
            props = obj.get("properties") or {}

            # Name extraction
            name = (
                props.get("name")
                or (props.get("names", {}).get("primary") if isinstance(props.get("names"), dict) else None)
                or props.get("name:en")
                or props.get("name_en")
                or props.get("label")
                or ""
            ).strip()

            if not name:
                return None

            country = (props.get("country") or props.get("is_in:country") or props.get("country_code") or "").strip()
            admin1 = (props.get("region") or props.get("state") or props.get("is_in:state") or props.get("admin1") or "").strip()
            subtype = (props.get("subtype") or props.get("place") or props.get("class") or "settlement").strip()

            return {
                "name": name,
                "country": country,
                "country_code": country[:2].upper() if country else "",
                "admin1": admin1,
                "lat": round(lat, 6),
                "lon": round(lon, 6),
                "timezone": "UTC",
                "subtype": subtype,
            }

        # 2. Flat dictionary format
        name = (obj.get("name") or obj.get("city") or obj.get("place_name") or "").strip()
        lat = obj.get("lat") or obj.get("latitude")
        lon = obj.get("lon") or obj.get("longitude") or obj.get("lng")

        if not name or lat is None or lon is None:
            return None

        try:
            lat_f = float(lat)
            lon_f = float(lon)
        except (ValueError, TypeError):
            return None

        country = (obj.get("country") or obj.get("adm0name") or "").strip()
        cc = (obj.get("country_code") or obj.get("iso_a2") or "").strip().upper()
        admin1 = (obj.get("admin1") or obj.get("state") or obj.get("region") or "").strip()
        tz = (obj.get("timezone") or "UTC").strip()

        return {
            "name": name,
            "country": country,
            "country_code": cc,
            "admin1": admin1,
            "lat": round(lat_f, 6),
            "lon": round(lon_f, 6),
            "timezone": tz,
            "subtype": obj.get("subtype") or obj.get("feature_type") or "place",
        }

    @classmethod
    def stream_file(cls, file_path: str | Path) -> Generator[Dict[str, Any], None, None]:
        """Stream places from an NDJSON file line by line without loading the entire file into memory."""
        p = Path(file_path)
        if not p.exists():
            return

        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                place = cls.parse_line(line)
                if place:
                    yield place

    @classmethod
    def ingest_and_merge(
        cls,
        ndjson_path: str | Path,
        target_json_path: str | Path,
        max_records: Optional[int] = None
    ) -> Tuple[int, int]:
        """
        Ingest records from NDJSON file and merge with existing JSON offline database.
        Returns: (new_added_count, total_places_count)
        """
        target_p = Path(target_json_path)
        existing_places: List[Dict[str, Any]] = []
        seen_keys: Set[Tuple[str, str, float, float]] = set()

        if target_p.exists():
            try:
                with open(target_p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for p in data.get("places", []):
                        name = p.get("name", "").strip().lower()
                        cc = p.get("country_code", "").strip().upper()
                        lat = round(float(p.get("lat", 0.0)), 2)
                        lon = round(float(p.get("lon", 0.0)), 2)
                        seen_keys.add((name, cc, lat, lon))
                        existing_places.append(p)
            except Exception:
                pass

        added_count = 0
        for place in cls.stream_file(ndjson_path):
            name = place.get("name", "").strip().lower()
            cc = place.get("country_code", "").strip().upper()
            lat = round(float(place.get("lat", 0.0)), 2)
            lon = round(float(place.get("lon", 0.0)), 2)
            key = (name, cc, lat, lon)

            if key not in seen_keys:
                seen_keys.add(key)
                existing_places.append(place)
                added_count += 1
                if max_records and added_count >= max_records:
                    break

        # Sort and write back
        existing_places.sort(key=lambda x: (x.get("country", ""), x.get("admin1", ""), x.get("name", "")))
        output_data = {
            "dataset_version": "2026.09.4-enhanced-ndjson-v5",
            "total_places": len(existing_places),
            "description": "Comprehensive offline geolocation database enriched with OpenStreetMap & Overture Maps settlements.",
            "places": existing_places,
        }

        with open(target_p, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        return added_count, len(existing_places)
