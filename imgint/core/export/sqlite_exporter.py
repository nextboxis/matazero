"""SQLite database exporter for indexing evidence records."""

from __future__ import annotations
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Union

from imgint.core.model.record import AnalysisRecord


class SqliteExporter:
    """Exports AnalysisRecord collections into relational SQLite databases for SQL querying."""

    @classmethod
    def export(cls, records: List[AnalysisRecord], db_path: str | Path) -> str:
        p = Path(db_path)
        p.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(str(p))
        cur = conn.cursor()

        # Create Schema
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS images (
                sha256 TEXT PRIMARY KEY,
                file_name TEXT,
                file_path TEXT,
                mime_type TEXT,
                verdict_label TEXT,
                confidence_score REAL,
                risk_level TEXT,
                is_authentic INTEGER,
                imported_at TEXT
            );

            CREATE TABLE IF NOT EXISTS metadata_fields (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                image_sha256 TEXT,
                standard TEXT,
                tag_id TEXT,
                tag_name TEXT,
                field_value TEXT,
                value_type TEXT,
                offset INTEGER,
                FOREIGN KEY (image_sha256) REFERENCES images(sha256)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                image_sha256 TEXT,
                tier INTEGER,
                name TEXT,
                confidence TEXT,
                extractor TEXT,
                value_json TEXT,
                FOREIGN KEY (image_sha256) REFERENCES images(sha256)
            );

            CREATE TABLE IF NOT EXISTS gps_locations (
                image_sha256 TEXT PRIMARY KEY,
                latitude REAL,
                longitude REAL,
                altitude_m REAL,
                timestamp TEXT,
                FOREIGN KEY (image_sha256) REFERENCES images(sha256)
            );
        """)

        now_iso = datetime.now(timezone.utc).isoformat()

        for rec in records:
            verdict_f = next((f.value for f in rec.findings if f.name == "authenticity_verdict" and isinstance(f.value, dict)), {})
            v_label = verdict_f.get("verdict_label", "UNVERIFIED")
            score = verdict_f.get("confidence_score", 0.5)
            risk = verdict_f.get("risk_level", "LOW")
            is_auth = 1 if verdict_f.get("is_authentic") is True else 0 if verdict_f.get("is_authentic") is False else None

            # Insert Image
            cur.execute("""
                INSERT OR REPLACE INTO images 
                (sha256, file_name, file_path, mime_type, verdict_label, confidence_score, risk_level, is_authentic, imported_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rec.sha256,
                Path(rec.file_path).name,
                rec.file_path,
                rec.mime_type,
                v_label,
                score,
                risk,
                is_auth,
                now_iso,
            ))

            # Insert Fields
            for fld in rec.fields:
                cur.execute("""
                    INSERT INTO metadata_fields 
                    (image_sha256, standard, tag_id, tag_name, field_value, value_type, offset)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    rec.sha256,
                    fld.standard,
                    fld.tag_id,
                    fld.name,
                    str(fld.value),
                    fld.value_type,
                    fld.offset,
                ))

            # Insert Findings
            for fnd in rec.findings:
                cur.execute("""
                    INSERT INTO findings 
                    (image_sha256, tier, name, confidence, extractor, value_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    rec.sha256,
                    fnd.tier,
                    fnd.name,
                    fnd.confidence.value if hasattr(fnd.confidence, "value") else str(fnd.confidence),
                    fnd.extractor,
                    json.dumps(fnd.value) if isinstance(fnd.value, (dict, list)) else str(fnd.value),
                ))

            # Insert GPS
            gps_f = next((f for f in rec.findings if f.name == "gps_coordinates_claimed"), None)
            if gps_f and isinstance(gps_f.value, dict):
                lat = gps_f.value.get("latitude")
                lon = gps_f.value.get("longitude")
                alt_f = next((f.value.get("altitude_meters") for f in rec.findings if f.name == "gps_altitude_claimed" and isinstance(f.value, dict)), None)
                date_f = next((str(f.value) for f in rec.fields if f.name in ("DateTimeOriginal", "DateTime")), None)
                if lat is not None and lon is not None:
                    cur.execute("""
                        INSERT OR REPLACE INTO gps_locations 
                        (image_sha256, latitude, longitude, altitude_m, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        rec.sha256,
                        lat,
                        lon,
                        alt_f,
                        date_f,
                    ))

        conn.commit()
        conn.close()
        return str(p.resolve())
