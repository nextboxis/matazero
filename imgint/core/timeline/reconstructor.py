"""Chronological timeline reconstruction and clock drift estimator."""

from __future__ import annotations
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from imgint.core.pipeline import AnalysisPipeline
from imgint.core.governance.scope import AuthorizationScope
from imgint.core.model.record import AnalysisRecord


@dataclass
class TimelineEvent:
    file_name: str
    file_path: str
    sha256: str
    primary_timestamp: datetime
    timestamp_source: str  # "EXIF_DateTimeOriginal", "EXIF_ModifyDate", "GPS_Satellite_UTC", "Filesystem_Mtime"
    raw_timestamp_str: str
    gps_satellite_time: Optional[datetime] = None
    camera_clock_drift_seconds: Optional[float] = None
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    gps_coordinates: Optional[Tuple[float, float]] = None
    time_delta_from_previous_sec: Optional[float] = None
    anomalies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["primary_timestamp"] = self.primary_timestamp.isoformat()
        if self.gps_satellite_time:
            d["gps_satellite_time"] = self.gps_satellite_time.isoformat()
        return d


@dataclass
class TimelineReport:
    total_events: int
    events: List[TimelineEvent]
    timespan_start: Optional[str]
    timespan_end: Optional[str]
    total_duration_str: Optional[str]
    detected_anomalies: List[str]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["events"] = [e.to_dict() for e in self.events]
        return d


class TimelineReconstructor:
    """Fuses multi-source timestamps across evidence images to reconstruct timelines and calculate clock drift."""

    @classmethod
    def reconstruct(
        cls,
        targets: List[str | Path],
        pipeline: Optional[AnalysisPipeline] = None,
    ) -> TimelineReport:
        if not pipeline:
            scope = AuthorizationScope.create_self_audit_scope()
            pipeline = AnalysisPipeline(scope=scope, selected_tiers={1, 5, 6})

        events: List[TimelineEvent] = []

        for t in targets:
            p = Path(t)
            if not p.is_file():
                continue
            try:
                rec = pipeline.analyze_file(p)
                event = cls._extract_event_from_record(p, rec)
                events.append(event)
            except Exception:
                # Fallback to filesystem mtime
                try:
                    stat = p.stat()
                    dt = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                    events.append(
                        TimelineEvent(
                            file_name=p.name,
                            file_path=str(p),
                            sha256="",
                            primary_timestamp=dt,
                            timestamp_source="Filesystem_Mtime",
                            raw_timestamp_str=dt.isoformat(),
                        )
                    )
                except Exception:
                    pass

        # Sort events chronologically by primary timestamp
        events.sort(key=lambda e: e.primary_timestamp)

        # Calculate time deltas and chronological anomalies
        anomalies: List[str] = []
        for i in range(len(events)):
            if i > 0:
                prev_event = events[i - 1]
                curr_event = events[i]
                delta_sec = (curr_event.primary_timestamp - prev_event.primary_timestamp).total_seconds()
                curr_event.time_delta_from_previous_sec = delta_sec

                # Detect filename sequence inversion vs timestamp
                # e.g., IMG_0005 taken BEFORE IMG_0004
                if prev_event.file_name > curr_event.file_name and delta_sec > 0:
                    pass  # Natural
                elif prev_event.file_name < curr_event.file_name and delta_sec < 0:
                    msg = f"Sequence Inversion: '{curr_event.file_name}' appears after '{prev_event.file_name}' alphabetically but has an earlier timestamp."
                    curr_event.anomalies.append(msg)
                    anomalies.append(msg)

            # Check clock drift anomaly
            if events[i].camera_clock_drift_seconds is not None:
                drift = events[i].camera_clock_drift_seconds
                if abs(drift) > 300:  # > 5 minutes drift
                    msg = f"Severe Camera Clock Drift in '{events[i].file_name}': Internal clock differs from GPS satellite time by {drift:+.1f}s ({drift/60.0:+.1f} mins)."
                    events[i].anomalies.append(msg)
                    anomalies.append(msg)

        start_str = events[0].primary_timestamp.isoformat() if events else None
        end_str = events[-1].primary_timestamp.isoformat() if events else None
        duration_str = None
        if events and len(events) > 1:
            total_sec = (events[-1].primary_timestamp - events[0].primary_timestamp).total_seconds()
            duration_str = str(timedelta(seconds=int(total_sec)))

        return TimelineReport(
            total_events=len(events),
            events=events,
            timespan_start=start_str,
            timespan_end=end_str,
            total_duration_str=duration_str,
            detected_anomalies=anomalies,
        )

    @classmethod
    def _extract_event_from_record(cls, file_path: Path, rec: AnalysisRecord) -> TimelineEvent:
        # Extract fields
        f_map = {f.name: f.value for f in rec.fields}
        
        # 1. Primary timestamp resolution
        dt_orig_raw = f_map.get("DateTimeOriginal")
        dt_mod_raw = f_map.get("ModifyDate") or f_map.get("DateTime")
        
        dt_primary = None
        ts_source = "Filesystem_Mtime"
        raw_str = ""

        if dt_orig_raw:
            dt_primary = cls._parse_datetime(str(dt_orig_raw), f_map.get("OffsetTimeOriginal") or f_map.get("OffsetTime"))
            if dt_primary:
                ts_source = "EXIF_DateTimeOriginal"
                raw_str = str(dt_orig_raw)

        if not dt_primary and dt_mod_raw:
            dt_primary = cls._parse_datetime(str(dt_mod_raw), f_map.get("OffsetTime"))
            if dt_primary:
                ts_source = "EXIF_ModifyDate"
                raw_str = str(dt_mod_raw)

        if not dt_primary:
            mtime = file_path.stat().st_mtime
            dt_primary = datetime.fromtimestamp(mtime, tz=timezone.utc)
            ts_source = "Filesystem_Mtime"
            raw_str = dt_primary.isoformat()

        # 2. GPS Satellite timestamp & Clock Drift
        gps_satellite_dt = None
        drift_seconds = None
        gps_date = f_map.get("GPSDateStamp")
        gps_time = f_map.get("GPSTimeStamp")

        if gps_date and gps_time:
            gps_satellite_dt = cls._parse_gps_datetime(str(gps_date), gps_time)
            if gps_satellite_dt and dt_primary:
                # Normalize dt_primary to UTC for drift comparison
                dt_utc = dt_primary if dt_primary.tzinfo else dt_primary.replace(tzinfo=timezone.utc)
                drift_seconds = round((dt_utc - gps_satellite_dt).total_seconds(), 2)

        # 3. GPS Coordinates
        gps_finding = next((f for f in rec.findings if f.name == "gps_coordinates_claimed"), None)
        coords = None
        if gps_finding and isinstance(gps_finding.value, dict):
            lat = gps_finding.value.get("latitude")
            lon = gps_finding.value.get("longitude")
            if lat is not None and lon is not None:
                coords = (lat, lon)

        make = str(f_map.get("Make")) if f_map.get("Make") else None
        model = str(f_map.get("Model")) if f_map.get("Model") else None

        return TimelineEvent(
            file_name=file_path.name,
            file_path=str(file_path),
            sha256=rec.sha256,
            primary_timestamp=dt_primary,
            timestamp_source=ts_source,
            raw_timestamp_str=raw_str,
            gps_satellite_time=gps_satellite_dt,
            camera_clock_drift_seconds=drift_seconds,
            camera_make=make,
            camera_model=model,
            gps_coordinates=coords,
        )

    @classmethod
    def _parse_datetime(cls, s: str, offset_str: Optional[str] = None) -> Optional[datetime]:
        clean = s.strip().split(".")[0]
        tz = timezone.utc
        if offset_str and ":" in offset_str:
            try:
                sign = -1 if offset_str.startswith("-") else 1
                parts = offset_str.lstrip("+-").split(":")
                hrs = int(parts[0])
                mins = int(parts[1])
                tz = timezone(sign * timedelta(hours=hrs, minutes=mins))
            except Exception:
                pass

        for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(clean, fmt)
                return dt.replace(tzinfo=tz)
            except Exception:
                pass
        return None

    @classmethod
    def _parse_gps_datetime(cls, date_str: str, time_val: Any) -> Optional[datetime]:
        try:
            # date_str is typically "YYYY:MM:DD" or "YYYY-MM-DD"
            date_clean = date_str.strip().replace("-", ":")
            parts = date_clean.split(":")
            year, month, day = int(parts[0]), int(parts[1]), int(parts[2])

            if isinstance(time_val, (list, tuple)) and len(time_val) >= 3:
                hour = int(time_val[0])
                minute = int(time_val[1])
                second = int(time_val[2])
            elif isinstance(time_val, str) and ":" in time_val:
                t_parts = time_val.split(":")
                hour, minute, second = int(t_parts[0]), int(t_parts[1]), int(float(t_parts[2]))
            else:
                return None

            return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
        except Exception:
            return None
