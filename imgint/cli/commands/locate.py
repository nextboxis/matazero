from __future__ import annotations
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from imgint import __version__
from imgint.cli.commands._utils import (
    resolve_scope,
    ExitCode,
    expand_targets,
    _expand_file_targets,
    IMAGE_EXTENSIONS,
)
from imgint.core.analyzer.tier5_geotime import GeoTimeAnalyzer
from imgint.core.evidence.store import EvidenceStore, EvidenceCustodyError
from imgint.core.governance.audit import AuditLogger, verify_audit_chain
from imgint.core.governance.scope import AuthorizationScope, ScopeValidationError
from imgint.core.pipeline import AnalysisPipeline, AnalysisRecord
from imgint.core.report.renderer import ReportRenderer
from imgint.core.report.manifest import HashManifestGenerator
from imgint.core.clean.cleaner import MetadataCleaner
from imgint.core.source.reader import BoundedReader
from imgint.core.sniff.detector import FormatDetector
from imgint.core.container import create_default_container_registry
from imgint.core.standard import create_default_standard_registry
from imgint.core.artefact.carver import PayloadCarver
from imgint.core.artefact.extractor import ArtefactExtractor, ExtractedItem
from imgint.core.fingerprint.corpus import ReferenceCorpus, CorpusEntry
from imgint.core.fingerprint.dqt import DqtExtractor
from imgint.core.fingerprint.subsampling import SubsamplingExtractor
from imgint.core.fingerprint.order import SegmentOrderExtractor
from imgint.core.geo.locator import GeoLocator
from imgint.core.geo.sqlite_engine import NaturalEarthDB
from imgint.core.geo.ndjson_ingester import NDJSONGeoIngester
from imgint.core.geo.exporter import GeoExporter
from imgint.core.report.cli_dashboard import CliDashboard
from imgint.core.diff import ForensicComparator, DiffRenderer
from imgint.core.stego import StegoInspector, StegoRenderer
from imgint.core.timeline import TimelineReconstructor, TimelineExporter
from imgint.core.motion import MotionPhotoDetector, MotionPhotoCarver, MotionPhotoRenderer
from imgint.core.cluster import ClusterEngine, ClusterRenderer
from imgint.core.export import SqliteExporter, StixExporter
from imgint.core.skill import SkillRegistry
from imgint.core.ai import OllamaClient, OllamaRenderer
from imgint.core.diag import DiagnosticRunner
from imgint.core.report import CaseDossierGenerator
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
import concurrent.futures

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

@click.command("locate")
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("-o", "--out", "out_file", default=None, type=click.Path(), help="Write output to destination file")
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "report", "json", "geojson", "html", "kml", "kmz", "gpx"]), default="table", help="Output format")
@click.option("-n", "--allow-network", is_flag=True, help="Enable online reverse geocoding via OpenStreetMap / Nominatim (GR-4.1)")
@click.option("-r", "--recursive", is_flag=True, help="Recursively search directory targets for images")
@click.option("--glob", "glob_pattern", default=None, help="Glob pattern to filter files (e.g. '*.jpg')")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode without an external scope")
@click.option("--geofence", "geofence_path", default=None, type=click.Path(exists=True), help="Path to GeoJSON file defining Area of Interest (AOI) / Geofence")
@click.option("--ip", "ip_query", default=None, help="Correlate image GPS with an IP address (e.g. 24.48.0.1, requires network or --ip-geo)")
@click.option("--ip-geo", "ip_geo_input", default=None, help="Path to IP Geolocation JSON file or raw JSON string")
@click.option("--sqlite", "sqlite_path", default=None, type=click.Path(exists=True), help="Path to Natural Earth Vector SQLite database")
def locate(
    targets: List[str],
    out_file: Optional[str],
    out_fmt: str,
    allow_network: bool,
    recursive: bool,
    glob_pattern: Optional[str],
    scope_path: Optional[str],
    self_audit: bool,
    geofence_path: Optional[str],
    ip_query: Optional[str],
    ip_geo_input: Optional[str],
    sqlite_path: Optional[str],
) -> None:
    """Forensic Geolocation, Reverse Geocoding, Solar Chronolocation, and Trajectory Intelligence."""
    if sqlite_path:
        NaturalEarthDB.get_instance(db_path=sqlite_path)

    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)

    resolved_targets = _expand_file_targets(targets, recursive=recursive, glob_pattern=glob_pattern)
    if not resolved_targets:
        err_console.print("[yellow]No matching image files found to locate.[/yellow]")
        return

    ip_geo_data: Optional[Dict[str, Any]] = None
    if ip_geo_input:
        ip_geo_data = GeoLocator.parse_ip_geolocation(ip_geo_input)
    elif ip_query and allow_network:
        ip_geo_data = GeoLocator.resolve_ip_online(ip_query)
    elif ip_query and not allow_network:
        err_console.print("[yellow]Notice: Online IP resolution requires --allow-network (-n). Use --ip-geo to provide offline JSON.[/yellow]")

    pipeline = AnalysisPipeline(scope=auth_scope, allow_network=allow_network, selected_tiers={1, 5})

    geo_points: List[Dict[str, Any]] = []

    for t_path in resolved_targets:
        try:
            rec = pipeline.analyze_file(t_path)
            gps_finding = next((f for f in rec.findings if f.name == "gps_coordinates_claimed"), None)
            if not gps_finding:
                for blk in rec.metadata_blocks:
                    if blk.kind == "EMBEDDED_IMAGE" and blk.raw_bytes:
                        try:
                            from imgint.core.standard.exif import ExifParser
                            sub_r = BoundedReader(blk.raw_bytes)
                            sub_d = FormatDetector.detect(sub_r)
                            if sub_d.is_supported:
                                sub_reg = create_default_container_registry()
                                sub_cr = sub_reg.get_reader(sub_d.format_name)
                                if sub_cr:
                                    _, sub_blks, _ = sub_cr.read(sub_r)
                                    for sb in sub_blks:
                                        if sb.kind in ("EXIF", "TIFF_EXIF"):
                                            _, sub_fnds, _ = ExifParser().parse(sb)
                                            sub_gps = next((f for f in sub_fnds if f.name == "gps_coordinates_claimed"), None)
                                            if sub_gps and sub_gps.value.get("latitude") is not None:
                                                gps_finding = sub_gps
                                                break
                        except Exception:
                            pass
                    if gps_finding:
                        break

            if not gps_finding:
                continue

            val = gps_finding.value
            lat = val.get("latitude")
            lon = val.get("longitude")
            if lat is None or lon is None:
                continue

            alt_finding = next((f for f in rec.findings if f.name == "gps_altitude_claimed"), None)
            alt_m = alt_finding.value.get("altitude_meters") if alt_finding else None

            make_f = next((f.value for f in rec.fields if f.name == "Make"), None)
            model_f = next((f.value for f in rec.fields if f.name == "Model"), None)
            date_f = next((f.value for f in rec.fields if f.name in ("DateTimeOriginal", "DateTime")), None)

            offline_geo = GeoLocator.reverse_geocode_offline(lat, lon) or {}
            online_geo = GeoLocator.reverse_geocode_online(lat, lon) if allow_network else None
            tz = GeoLocator.get_timezone(lat, lon)
            map_links = GeoLocator.get_map_links(lat, lon)

            solar_finding = next((f for f in rec.findings if f.name == "solar_position_expected"), None)
            solar_info = solar_finding.value if solar_finding else None

            point_record = {
                "file_name": t_path.name,
                "file_path": str(t_path),
                "sha256": rec.sha256,
                "latitude": lat,
                "longitude": lon,
                "x": lon,
                "y": lat,
                "latitude_ref": val.get("latitude_ref", "N"),
                "longitude_ref": val.get("longitude_ref", "E"),
                "x_value_location": val.get("x_value_location"),
                "y_value_location": val.get("y_value_location"),
                "altitude_m": alt_m,
                "timestamp": str(date_f) if date_f else None,
                "camera_make": str(make_f) if make_f else None,
                "camera_model": str(model_f) if model_f else None,
                "closest_city": offline_geo.get("closest_city"),
                "admin_region": offline_geo.get("admin_region"),
                "country": offline_geo.get("country"),
                "country_code": offline_geo.get("country_code"),
                "timezone": tz,
                "approx_distance_to_city_km": offline_geo.get("approx_distance_km"),
                "online_address": online_geo.get("display_name") if online_geo else None,
                "solar_chronolocation": solar_info,
                "map_links": map_links,
            }
            try:
                fac_ctx = GeoLocator.get_facility_context(lat, lon)
                if fac_ctx.get("has_facility_proximity"):
                    point_record["facility_proximity"] = fac_ctx
            except Exception:
                pass

            try:
                cone_finding = next((f for f in rec.findings if f.name == "optical_viewing_cone"), None)
                if cone_finding and isinstance(cone_finding.value, dict):
                    point_record["optical_viewing_cone"] = cone_finding.value
                else:
                    img_dir_f = next((f.value for f in rec.fields if f.name == "GPSImgDirection"), None)
                    if img_dir_f is not None:
                        gta = GeoTimeAnalyzer()
                        img_dir_v = gta._convert_rational_to_float(img_dir_f)
                        fl_val = next((f.value for f in rec.fields if f.name == "FocalLength"), None)
                        fl35_val = next((f.value for f in rec.fields if f.name == "FocalLengthIn35mmFilm"), None)
                        f_mm_v = gta._convert_rational_to_float(fl_val) if fl_val else None
                        f_35_v = gta._convert_rational_to_float(fl35_val) if fl35_val else None
                        dir_ref = str(next((f.value for f in rec.fields if f.name == "GPSImgDirectionRef"), "T") or "T")
                        from imgint.core.geo.optical import OpticalRayCaster
                        cone = OpticalRayCaster.calculate_viewing_cone(
                            lat=lat,
                            lon=lon,
                            heading_deg=img_dir_v,
                            heading_ref=dir_ref,
                            focal_length_35mm=f_35_v,
                            focal_length_mm=f_mm_v,
                        )
                        point_record["optical_viewing_cone"] = cone.to_dict()
            except Exception:
                pass

            if geofence_path:
                try:
                    gf_check = GeoLocator.is_point_in_geofence(val.get("latitude"), val.get("longitude"), geofence_path)
                    point_record["geofence_status"] = "INSIDE" if gf_check.get("inside_geofence") else "BREACH / OUTSIDE"
                    point_record["geofence_boundary"] = gf_check.get("matched_feature_name")
                except Exception:
                    pass
            if ip_geo_data:
                try:
                    ip_corr = GeoLocator.correlate_gps_with_ip(val.get("latitude"), val.get("longitude"), ip_geo_data)
                    if ip_corr:
                        point_record["ip_correlation"] = ip_corr
                except Exception:
                    pass
            geo_points.append(point_record)

        except Exception as e:
            err_console.print(f"[red]Error locating {t_path}: {e}[/red]")

    if not geo_points:
        console.print(f"[yellow]No GPS coordinate metadata found in {len(resolved_targets)} inspected file(s).[/yellow]")
        return

    trajectory_steps: List[Dict[str, Any]] = []
    velocity_anomalies: List[Dict[str, Any]] = []

    if len(geo_points) > 1:
        for i in range(len(geo_points) - 1):
            p1 = geo_points[i]
            p2 = geo_points[i + 1]
            dist = GeoLocator.compute_distance(p1["latitude"], p1["longitude"], p2["latitude"], p2["longitude"])
            bearing = GeoLocator.compute_bearing(p1["latitude"], p1["longitude"], p2["latitude"], p2["longitude"])

            step = {
                "from_file": p1["file_name"],
                "to_file": p2["file_name"],
                "distance_km": dist["distance_km"],
                "distance_miles": dist["distance_miles"],
                "bearing_deg": bearing["bearing_degrees"],
                "cardinal": bearing["cardinal_direction"],
                "time_delta_sec": None,
                "speed_kmh": None,
            }

            if p1.get("timestamp") and p2.get("timestamp"):
                try:
                    dt1 = GeoLocator.parse_datetime(p1["timestamp"])
                    dt2 = GeoLocator.parse_datetime(p2["timestamp"])
                    if dt1 and dt2:
                        dt_diff = (dt2 - dt1).total_seconds()
                        step["time_delta_sec"] = abs(dt_diff)
                        if abs(dt_diff) > 0:
                            speed = (dist["distance_km"] / (abs(dt_diff) / 3600.0))
                            step["speed_kmh"] = round(speed, 1)
                            if speed > 1000.0:
                                anomaly = {
                                    "pair": f"{p1['file_name']} -> {p2['file_name']}",
                                    "distance_km": dist["distance_km"],
                                    "time_diff_sec": abs(dt_diff),
                                    "speed_kmh": round(speed, 1),
                                    "warning": "Physically impossible transit velocity (>1,000 km/h) indicates GPS spoofing or clock alteration.",
                                }
                                velocity_anomalies.append(anomaly)
                except Exception:
                    pass

            trajectory_steps.append(step)

    rendered = ""
    if out_fmt == "geojson":
        rendered = json.dumps(GeoExporter.to_geojson(geo_points, geofence_geojson=geofence_path), indent=2)
    elif out_fmt == "html":
        rendered = GeoExporter.to_leaflet_html(geo_points, geofence_geojson=geofence_path)
    elif out_fmt == "kml":
        rendered = GeoExporter.to_kml(geo_points)
    elif out_fmt == "kmz":
        dest_kmz = out_file or "matazero_dossier.kmz"
        GeoExporter.to_kmz(geo_points, output_kmz_path=dest_kmz)
        console.print(f"[green][OK] Successfully exported 3D Google Earth KMZ dossier to [bold]{dest_kmz}[/bold][/green]")
        return
    elif out_fmt == "gpx":
        rendered = GeoExporter.to_gpx(geo_points)
    elif out_fmt == "json":
        rendered = json.dumps({
            "total_points": len(geo_points),
            "points": geo_points,
            "trajectory": trajectory_steps,
            "velocity_anomalies": velocity_anomalies,
        }, indent=2)
    elif out_fmt == "report":
        lines = [
            "================================================================================",
            f"           matazero GEOLOCATION & CHRONOLOCATION DOSSIER ({len(geo_points)} Assets)",
            "================================================================================",
            "",
        ]
        for idx, pt in enumerate(geo_points, start=1):
            dms_str = GeoLocator.format_dms(pt["latitude"], pt["longitude"])
            lines.append(f"[{idx}] {pt['file_name']} (SHA-256: {pt['sha256'][:16]}...)")
            lines.append(f"    GPS Coordinates:      {pt['latitude']:.6f}, {pt['longitude']:.6f}  ({dms_str})")
            lines.append(f"    Google Maps:          {pt['map_links']['google_maps']}")
            lines.append(f"    OpenStreetMap:        {pt['map_links']['openstreetmap']}")
            if pt.get("altitude_m") is not None:
                lines.append(f"    Altitude:             {pt['altitude_m']} meters")
            if pt.get("geofence_status"):
                lines.append(f"    Geofence Status:      {pt['geofence_status']} ({pt.get('geofence_boundary', 'N/A')})")
            if pt.get("ip_correlation"):
                ipc = pt["ip_correlation"]
                ipi = ipc.get("ip_info", {})
                lines.append(f"    IP Correlation:       {ipc['correlation_verdict']} -> Δ {ipc['distance_km']} km ({ipc['distance_miles']} mi) from IP {ipi.get('ip')} ({ipi.get('city')}, {ipi.get('country')})")
                lines.append(f"    IP Provider:          {ipi.get('isp')} | ASN: {ipi.get('autonomous_system')}")
                lines.append(f"    Correlation Verdict:  {ipc['explanation']}")
            if pt.get("closest_city"):
                lines.append(f"    Location (Offline):   {pt['closest_city']}, {pt.get('admin_region', '')}, {pt.get('country', '')} (~{pt.get('approx_distance_to_city_km')} km)")
            if pt.get("online_address"):
                lines.append(f"    Address (OSM):        {pt['online_address']}")
            if pt.get("timezone"):
                lines.append(f"    Timezone:             {pt['timezone']}")
            if pt.get("timestamp"):
                lines.append(f"    Capture Timestamp:    {pt['timestamp']}")
            if pt.get("solar_chronolocation"):
                sol = pt["solar_chronolocation"]
                lines.append(f"    Solar Position:       Azimuth = {sol.get('solar_azimuth_degrees')}°, Elevation = {sol.get('solar_elevation_degrees')}° ({sol.get('day_phase', 'Daylight')})")
            lines.append("")

        if trajectory_steps:
            lines.append("--------------------------------------------------------------------------------")
            lines.append("                         INTER-ASSET TRAJECTORY ANALYSIS                        ")
            lines.append("--------------------------------------------------------------------------------")
            for st in trajectory_steps:
                spd_str = f" | Speed: {st['speed_kmh']} km/h" if st.get("speed_kmh") is not None else ""
                lines.append(f" • {st['from_file']} -> {st['to_file']}: {st['distance_km']} km ({st['distance_miles']} mi) @ {st['bearing_deg']}° {st['cardinal']}{spd_str}")
            lines.append("")

        if velocity_anomalies:
            lines.append("================================================================================")
            lines.append("                 [!] VELOCITY & TRAVEL IMPOSSIBILITY ANOMALIES                  ")
            lines.append("================================================================================")
            for an in velocity_anomalies:
                lines.append(f" [!] ANOMALY: {an['pair']} -> Velocity: {an['speed_kmh']:,} km/h")
                lines.append(f"     Details: {an['distance_km']} km in {an['time_diff_sec']} seconds")
                lines.append(f"     Verdict: {an['warning']}\n")

        rendered = "\n".join(lines)

    else:
        console.print(f"[bold cyan]matazero Geolocation Intelligence[/bold cyan] — {len(geo_points)} Points Found\n")

        pt_table = Table(title=f"Located Evidence Assets ({len(geo_points)})")
        pt_table.add_column("#", justify="right", style="dim")
        pt_table.add_column("File Name", style="bold green")
        pt_table.add_column("GPS (Lat, Lon)", justify="center", style="bold white")
        pt_table.add_column("Nearest City", style="yellow")
        pt_table.add_column("Timezone", style="white")
        pt_table.add_column("Day Phase", style="magenta")
        if geofence_path:
            pt_table.add_column("Geofence", style="bold")
        if ip_geo_data:
            pt_table.add_column("IP Correlation", style="bold")
        pt_table.add_column("Capture Time", style="dim")

        for idx, pt in enumerate(geo_points, start=1):
            day_ph = pt.get("solar_chronolocation", {}).get("day_phase", "-") if pt.get("solar_chronolocation") else "-"
            row = [
                str(idx),
                pt["file_name"],
                f"{pt['latitude']:.6f}, {pt['longitude']:.6f}",
                pt.get("closest_city") or "-",
                pt.get("timezone") or "-",
                day_ph,
            ]
            if geofence_path:
                gf_st = pt.get("geofence_status", "-")
                gf_style = "[green]INSIDE[/green]" if "INSIDE" in gf_st else "[bold red]BREACH[/bold red]"
                row.append(gf_style)
            if ip_geo_data:
                ipc = pt.get("ip_correlation")
                if ipc:
                    dist_k = ipc["distance_km"]
                    if ipc["is_suspicious"]:
                        row.append(f"[bold red]Δ {dist_k:,.0f}km (DISCREPANCY)[/bold red]")
                    else:
                        row.append(f"[green]Δ {dist_k:.1f}km ({ipc['correlation_verdict']})[/green]")
                else:
                    row.append("-")
            row.append(pt.get("timestamp") or "-")
            pt_table.add_row(*row)
        console.print(pt_table)

        if trajectory_steps:
            console.print("")
            tr_table = Table(title=f"Movement & Trajectory Transition Steps ({len(trajectory_steps)})")
            tr_table.add_column("From", style="cyan")
            tr_table.add_column("To", style="cyan")
            tr_table.add_column("Distance (km)", justify="right", style="bold green")
            tr_table.add_column("Bearing", justify="right", style="yellow")
            tr_table.add_column("Transit Speed", justify="right", style="magenta")
            for st in trajectory_steps:
                spd_s = f"{st['speed_kmh']:.1f} km/h" if st.get("speed_kmh") is not None else "-"
                tr_table.add_row(
                    st["from_file"],
                    st["to_file"],
                    f"{st['distance_km']:,.2f} km",
                    f"{st['bearing_deg']}° {st['cardinal']}",
                    spd_s,
                )
            console.print(tr_table)

        if velocity_anomalies:
            console.print("")
            for an in velocity_anomalies:
                console.print(f"[bold red][!] TRAVEL ANOMALY ({an['pair']}): Velocity = {an['speed_kmh']:,} km/h ({an['distance_km']} km in {an['time_diff_sec']}s)[/bold red]")
                console.print(f"    [yellow]{an['warning']}[/yellow]")

        rendered = ""

    if rendered:
        if out_file:
            Path(out_file).write_text(rendered, encoding="utf-8")
            console.print(f"[green][OK] Geolocation intelligence written to {out_file}[/green]")
        else:
            print(rendered)


