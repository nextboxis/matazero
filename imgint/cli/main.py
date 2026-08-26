"""Command-line interface for imgint per SRD §3.10 and SRS §3.1."""

from __future__ import annotations
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.table import Table

from imgint import __version__
from imgint.core.evidence.store import EvidenceStore, EvidenceCustodyError
from imgint.core.governance.audit import AuditLogger, verify_audit_chain
from imgint.core.governance.scope import AuthorizationScope, ScopeValidationError
from imgint.core.pipeline import AnalysisPipeline
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
from imgint.core.geo.exporter import GeoExporter
from imgint.core.report.cli_dashboard import CliDashboard
import concurrent.futures

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)


@click.group()
@click.version_option(version=__version__, prog_name="matazero")
def cli() -> None:
    """matazero — Image Intelligence Toolkit for Ethical OSINT and Digital Forensics."""
    pass


# -----------------------------------------------------------------------------
# Subcommand: scope
# -----------------------------------------------------------------------------
@cli.group()
def scope() -> None:
    """Create, validate, or display an authorization scope."""
    pass


@scope.command("create")
@click.option("-c", "--case", "case_id", required=True, help="Case identifier (e.g. CASE-2026-001)")
@click.option("-p", "--purpose", required=True, help="Investigation purpose")
@click.option("-l", "--legal-basis", required=True, help="Lawful basis (e.g. Subpoena, Consent, Legitimate Interest)")
@click.option("-a", "--authorising-party", required=True, help="Authorising authority / lead investigator")
@click.option("-d", "--days", default=30, type=int, help="Validity period in days (default: 30)")
@click.option("-o", "--out", "out_path", required=True, type=click.Path(), help="Output path for scope JSON file")
@click.option("-k", "--secret", default=None, help="Optional HMAC secret key for cryptographic signing")
def scope_create(case_id: str, purpose: str, legal_basis: str, authorising_party: str, days: int, out_path: str, secret: Optional[str]) -> None:
    """Create a new signed authorization scope file."""
    exp_date = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    auth_scope = AuthorizationScope(
        case_id=case_id,
        purpose=purpose,
        legal_basis=legal_basis,
        authorising_party=authorising_party,
        data_subject_categories=["Image Source Files"],
        permitted_operations=["tier1", "tier2", "tier3", "tier4", "tier5", "tier6", "tier7"],
        retention_period_days=days,
        expiry_date=exp_date,
    )
    auth_scope.save_to_file(out_path, secret_key=secret)
    console.print(f"[green][OK][/green] Authorization scope created at [bold]{out_path}[/bold]")
    console.print(f"  Case ID:     {case_id}")
    console.print(f"  Expiry:      {exp_date}")
    console.print(f"  Scope Hash:  {auth_scope.scope_hash}")
    if secret:
        console.print(f"  Signature:   {auth_scope.signature}")


@scope.command("validate")
@click.argument("scope_file", type=click.Path(exists=True))
@click.option("-k", "--secret", default=None, help="Optional HMAC secret key for signature verification")
def scope_validate(scope_file: str, secret: Optional[str]) -> None:
    """Validate the integrity and expiration status of a scope file."""
    try:
        s = AuthorizationScope.load_from_file(scope_file, secret_key=secret)
        console.print(f"[green][OK] Scope is VALID[/green]")
        console.print(f"  Case ID:     {s.case_id}")
        console.print(f"  Purpose:     {s.purpose}")
        console.print(f"  Legal Basis: {s.legal_basis}")
        console.print(f"  Expires:     {s.expiry_date}")
        console.print(f"  Scope Hash:  {s.scope_hash}")
    except ScopeValidationError as e:
        err_console.print(f"[red][X] Scope INVALID: {e}[/red]")
        sys.exit(6)


# -----------------------------------------------------------------------------
# Subcommand: analyze
IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".webp", ".heic", ".tiff", ".tif",
    ".cr2", ".nef", ".arw", ".dng", ".jxl", ".avif", ".bmp", ".gif",
    ".pptx", ".ppsx", ".docx", ".xlsx", ".zip", ".odp", ".psd", ".svg"
}


def _expand_file_targets(targets: List[str], recursive: bool = False, glob_pattern: Optional[str] = None) -> List[Path]:
    """Expands list of files and directory paths into list of image files."""
    expanded: List[Path] = []
    seen = set()
    for t in targets:
        p = Path(t)
        if p.is_file():
            if p.resolve() not in seen:
                seen.add(p.resolve())
                expanded.append(p)
        elif p.is_dir():
            pattern = glob_pattern or "*"
            iterator = p.rglob(pattern) if recursive else p.glob(pattern)
            for item in iterator:
                if item.is_file() and (glob_pattern or item.suffix.lower() in IMAGE_EXTENSIONS):
                    if item.resolve() not in seen:
                        seen.add(item.resolve())
                        expanded.append(item)
    return expanded


def _apply_record_filter(rec, filter_expr: Optional[str]) -> bool:
    """Applies high-level forensic query filters to analysis records."""
    if not filter_expr:
        return True
    expr = filter_expr.strip().lower()
    if expr in ("has_gps", "gps"):
        return any(f.name == "gps_coordinates_claimed" for f in rec.findings)
    if expr in ("has_payload", "payload", "carve"):
        return any(f.name == "trailing_data_detected" for f in rec.findings)
    if expr in ("authentic=false", "modified", "tampered"):
        return any(f.name == "authenticity_verdict" and f.value.get("is_authentic") is False for f in rec.findings)
    if expr in ("authentic=true", "authentic"):
        return any(f.name == "authenticity_verdict" and f.value.get("is_authentic") is True for f in rec.findings)
    if expr.startswith("tier="):
        try:
            t_num = int(expr.split("=")[1])
            return any(f.tier == t_num for f in rec.findings)
        except Exception:
            pass
    return True


def _apply_field_selection(rec, select_fields: Optional[str]) -> None:
    """Filters metadata fields to only requested field names."""
    if not select_fields:
        return
    names = {n.strip().lower() for n in select_fields.split(",") if n.strip()}
    rec.fields = [
        f for f in rec.fields
        if f.name.lower() in names or (f.tag_id and f.tag_id.lower() in names)
    ]


# -----------------------------------------------------------------------------
# Subcommand: analyze
# -----------------------------------------------------------------------------
@cli.command("analyze")
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode on personal files without a scope")
@click.option("-t", "--tiers", default="1,2,3,4,5,6,7", help="Comma-separated tier list (e.g. 1,2,3)")
@click.option("-f", "--format", "out_fmt", type=click.Choice(["report", "dashboard", "deep", "summary", "text", "json", "ndjson", "table", "html"]), default="report", help="Output format")
@click.option("--deep", "--details", "deep_mode", is_flag=True, help="Display exhaustive hierarchical forensic tree breakdown")
@click.option("--summary", is_flag=True, help="Display executive visual summary dashboard")
@click.option("--store", "store_path", default="./evidence_store", help="Evidence store directory")
@click.option("--audit-log", "audit_path", default="./audit.jsonl", help="Audit log file path")
@click.option("-n", "--allow-network", is_flag=True, help="Enable disclosed external lookups (GR-4.1)")
@click.option("-e", "--ela", is_flag=True, help="Enable Error Level Analysis in Tier 6")
@click.option("-c", "--carve", is_flag=True, help="Automatically carve trailing archives or payloads")
@click.option("--carve-dir", default="./evidence_store/carved", help="Directory to save carved payloads")
@click.option("-r", "--recursive", is_flag=True, help="Recursively search directory targets for images")
@click.option("--glob", "glob_pattern", default=None, help="Glob pattern to filter files (e.g. '*.jpg')")
@click.option("--filter", "filter_expr", default=None, help="Filter records (e.g. 'has_gps', 'has_payload', 'authentic=false', 'tier=5')")
@click.option("--select-fields", default=None, help="Comma-separated list of metadata fields to include (e.g. 'Make,Model,GPSInfo')")
@click.option("-j", "--jobs", default=1, type=int, help="Number of concurrent worker threads (default: 1)")
@click.option("-o", "--out", "out_file", default=None, type=click.Path(), help="Write output to file instead of stdout")
def analyze(
    targets: List[str],
    scope_path: Optional[str],
    self_audit: bool,
    tiers: str,
    out_fmt: str,
    deep_mode: bool,
    summary: bool,
    store_path: str,
    audit_path: str,
    allow_network: bool,
    ela: bool,
    carve: bool,
    carve_dir: str,
    recursive: bool,
    glob_pattern: Optional[str],
    filter_expr: Optional[str],
    select_fields: Optional[str],
    jobs: int,
    out_file: Optional[str],
) -> None:
    """Run 7 extraction tiers over evidence files."""
    # Scope resolution
    auth_scope: Optional[AuthorizationScope] = None
    if self_audit:
        auth_scope = AuthorizationScope.create_self_audit_scope()
    elif scope_path:
        try:
            auth_scope = AuthorizationScope.load_from_file(scope_path)
        except ScopeValidationError as e:
            err_console.print(f"[red]Authorization failure (Exit 6): {e}[/red]")
            sys.exit(6)
    else:
        err_console.print(
            "[red]Authorization failure (Exit 6): No authorization scope provided.\n"
            "Provide --scope PATH, set IMGINT_SCOPE, or use --self-audit for personal files.[/red]"
        )
        sys.exit(6)

    # Initialize store and audit log
    evidence_store = EvidenceStore(store_path) if not self_audit else None
    audit_logger = AuditLogger(audit_path, scope_id=auth_scope.case_id) if not self_audit else None

    # Parse tiers
    try:
        tier_set = {int(t.strip()) for t in tiers.split(",") if t.strip()}
    except ValueError:
        err_console.print("[red]Invalid --tiers value. Expected numbers separated by comma (e.g. 1,2,3)[/red]")
        sys.exit(2)

    pipeline = AnalysisPipeline(
        scope=auth_scope,
        audit_logger=audit_logger,
        evidence_store=evidence_store,
        allow_network=allow_network,
        enable_ela=ela,
        selected_tiers=tier_set,
    )

    resolved_targets = _expand_file_targets(targets, recursive=recursive, glob_pattern=glob_pattern)
    if not resolved_targets:
        err_console.print("[yellow]No matching image evidence files found to analyze.[/yellow]")
        return

    records = []
    has_error = False

    def _process_one(target_path: Path):
        try:
            rec = pipeline.analyze_file(target_path)
            if carve and rec.structural_units:
                reader = BoundedReader(target_path)
                carved = PayloadCarver.carve_trailing_payload(reader, rec.structural_units, carve_dir)
                if carved:
                    console.print(
                        f"[green][OK] Carved {carved.payload_type} ({carved.size:,} B) from {target_path.name} -> [bold]{carved.output_path}[/bold][/green]"
                    )
            return rec, None
        except EvidenceCustodyError as e:
            return None, ("custody", str(e))
        except Exception as e:
            return None, ("error", f"Analysis error for {target_path}: {e}")

    if jobs > 1 and len(resolved_targets) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
            future_to_target = {executor.submit(_process_one, t): t for t in resolved_targets}
            for fut in concurrent.futures.as_completed(future_to_target):
                rec, err = fut.result()
                if err:
                    if err[0] == "custody":
                        err_console.print(f"[bold red]CRITICAL CUSTODY FAILURE (Exit 7): {err[1]}[/bold red]")
                        sys.exit(7)
                    else:
                        err_console.print(f"[red]{err[1]}[/red]")
                        has_error = True
                elif rec:
                    if _apply_record_filter(rec, filter_expr):
                        _apply_field_selection(rec, select_fields)
                        records.append(rec)
    else:
        for target_path in resolved_targets:
            rec, err = _process_one(target_path)
            if err:
                if err[0] == "custody":
                    err_console.print(f"[bold red]CRITICAL CUSTODY FAILURE (Exit 7): {err[1]}[/bold red]")
                    sys.exit(7)
                else:
                    err_console.print(f"[red]{err[1]}[/red]")
                    has_error = True
            elif rec:
                if _apply_record_filter(rec, filter_expr):
                    _apply_field_selection(rec, select_fields)
                    records.append(rec)

    if not records:
        if filter_expr:
            console.print(f"[yellow]No records matched the filter criteria: '{filter_expr}'[/yellow]")
        return

    # Render output
    if deep_mode or out_fmt == "deep":
        for r in records:
            CliDashboard.render_deep_tree(r, console)
        rendered = ""
    elif summary or out_fmt in ("dashboard", "summary"):
        for r in records:
            CliDashboard.render_summary_dashboard(r, console)
        rendered = ""
    elif out_fmt == "json":
        rendered = ReportRenderer.render_json(records)
    elif out_fmt == "ndjson":
        rendered = ReportRenderer.render_ndjson(records)
    elif out_fmt == "html":
        rendered = ReportRenderer.render_html(records)
    elif out_fmt == "table":
        table = Table(title=f"matazero Analysis Summary ({len(records)} Files)")
        table.add_column("File Path", style="cyan")
        table.add_column("Format", style="green")
        table.add_column("Findings", justify="right")
        table.add_column("SHA-256", style="dim")
        for r in records:
            table.add_row(r.file_path, r.mime_type, str(len(r.findings)), r.sha256[:16] + "...")
        console.print(table)
        rendered = ""
    else:  # report / text
        if out_file or out_fmt == "text":
            rendered = "\n\n".join(ReportRenderer.render_report(r) for r in records)
        else:
            # Interactive terminal report: render clean executive summary dashboard
            for r in records:
                CliDashboard.render_summary_dashboard(r, console)
            rendered = ""

    if rendered:
        if out_file:
            Path(out_file).write_text(rendered, encoding="utf-8")
            console.print(f"[green][OK] Output written to {out_file}[/green]")
        else:
            print(rendered)

    if has_error:
        sys.exit(4)  # Partial success


# -----------------------------------------------------------------------------
# Subcommand: locate (Forensic Geolocation & Chronolocation Intelligence)
# -----------------------------------------------------------------------------
@cli.command("locate")
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("-o", "--out", "out_file", default=None, type=click.Path(), help="Write output to destination file")
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "report", "json", "geojson", "html", "gpx"]), default="table", help="Output format")
@click.option("-n", "--allow-network", is_flag=True, help="Enable online reverse geocoding via OpenStreetMap / Nominatim (GR-4.1)")
@click.option("-r", "--recursive", is_flag=True, help="Recursively search directory targets for images")
@click.option("--glob", "glob_pattern", default=None, help="Glob pattern to filter files (e.g. '*.jpg')")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode without an external scope")
def locate(
    targets: List[str],
    out_file: Optional[str],
    out_fmt: str,
    allow_network: bool,
    recursive: bool,
    glob_pattern: Optional[str],
    scope_path: Optional[str],
    self_audit: bool,
) -> None:
    """Forensic Geolocation, Reverse Geocoding, Solar Chronolocation, and Trajectory Intelligence."""
    # Scope resolution
    if self_audit:
        auth_scope = AuthorizationScope.create_self_audit_scope()
    elif scope_path:
        try:
            auth_scope = AuthorizationScope.load_from_file(scope_path)
        except ScopeValidationError as e:
            err_console.print(f"[red]Authorization failure (Exit 6): {e}[/red]")
            sys.exit(6)
    else:
        auth_scope = AuthorizationScope.create_self_audit_scope()

    resolved_targets = _expand_file_targets(targets, recursive=recursive, glob_pattern=glob_pattern)
    if not resolved_targets:
        err_console.print("[yellow]No matching image files found to locate.[/yellow]")
        return

    pipeline = AnalysisPipeline(scope=auth_scope, allow_network=allow_network, selected_tiers={1, 5})

    geo_points: List[Dict[str, Any]] = []

    for t_path in resolved_targets:
        try:
            rec = pipeline.analyze_file(t_path)
            gps_finding = next((f for f in rec.findings if f.name == "gps_coordinates_claimed"), None)
            if not gps_finding:
                # Check embedded slide images inside presentations/documents
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

            # Capture timestamp & camera
            make_f = next((f.value for f in rec.fields if f.name == "Make"), None)
            model_f = next((f.value for f in rec.fields if f.name == "Model"), None)
            date_f = next((f.value for f in rec.fields if f.name in ("DateTimeOriginal", "DateTime")), None)

            # Reverse geocoding
            offline_geo = GeoLocator.reverse_geocode_offline(lat, lon) or {}
            online_geo = GeoLocator.reverse_geocode_online(lat, lon) if allow_network else None
            tz = GeoLocator.get_timezone(lat, lon)
            map_links = GeoLocator.get_map_links(lat, lon)

            # Solar calculation
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
            geo_points.append(point_record)

        except Exception as e:
            err_console.print(f"[red]Error locating {t_path}: {e}[/red]")

    if not geo_points:
        console.print(f"[yellow]No GPS coordinate metadata found in {len(resolved_targets)} inspected file(s).[/yellow]")
        return

    # Multi-target trajectory analysis (sequential distances, bearings, velocity checks)
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

            # Velocity check if timestamps present
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
                            if speed > 1000.0:  # Supersonic transit anomaly
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

    # Format output
    rendered = ""
    if out_fmt == "geojson":
        rendered = json.dumps(GeoExporter.to_geojson(geo_points), indent=2)
    elif out_fmt == "html":
        rendered = GeoExporter.to_leaflet_html(geo_points)
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
            lines.append(f"[{idx}] {pt['file_name']} (SHA-256: {pt['sha256'][:16]}...)")
            lines.append(f"    Coordinates (X, Y):   X = {pt['x']}° (Lon), Y = {pt['y']}° (Lat)")
            if pt.get("altitude_m") is not None:
                lines.append(f"    Altitude:             {pt['altitude_m']} meters")
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
            lines.append(f"    Map (OpenStreetMap):  {pt['map_links']['openstreetmap']}")
            lines.append(f"    Map (Google Maps):    {pt['map_links']['google_maps']}")
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

    else:  # table
        console.print(f"[bold cyan]matazero Geolocation Intelligence[/bold cyan] — {len(geo_points)} Points Found\n")

        pt_table = Table(title=f"Located Evidence Assets ({len(geo_points)})")
        pt_table.add_column("#", justify="right", style="dim")
        pt_table.add_column("File Name", style="bold green")
        pt_table.add_column("Latitude (Y)", justify="right", style="cyan")
        pt_table.add_column("Longitude (X)", justify="right", style="cyan")
        pt_table.add_column("Nearest City", style="yellow")
        pt_table.add_column("Timezone", style="white")
        pt_table.add_column("Day Phase", style="magenta")
        pt_table.add_column("Capture Time", style="dim")

        for idx, pt in enumerate(geo_points, start=1):
            day_ph = pt.get("solar_chronolocation", {}).get("day_phase", "-") if pt.get("solar_chronolocation") else "-"
            pt_table.add_row(
                str(idx),
                pt["file_name"],
                f"{pt['y']:.5f}°",
                f"{pt['x']:.5f}°",
                pt.get("closest_city") or "-",
                pt.get("timezone") or "-",
                day_ph,
                pt.get("timestamp") or "-",
            )
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


# -----------------------------------------------------------------------------
# Subcommand: probe
# -----------------------------------------------------------------------------
@cli.command("probe")
@click.argument("target", type=click.Path(exists=True))
def probe(target: str) -> None:
    """Dump container segment and chunk structure with byte offsets."""
    p = Path(target)
    reader = BoundedReader(p)
    detected = FormatDetector.detect(reader)

    console.print(f"[bold cyan]matazero Container Probe[/bold cyan] — {p.name} ({detected.format_name})")
    console.print(f"MIME: {detected.mime_type} | Size: {reader.size:,} bytes | Magic: {detected.magic_hex}\n")

    registry = create_default_container_registry()
    container_reader = registry.get_reader(detected.format_name)
    if not container_reader:
        err_console.print(f"[red]Unsupported container format: {detected.format_name}[/red]")
        sys.exit(3)

    units, blocks, diags = container_reader.read(reader)

    table = Table(title=f"Structural Units ({len(units)})")
    table.add_column("Offset", style="dim", justify="right")
    table.add_column("Unit Name", style="bold green")
    table.add_column("Length", justify="right")
    table.add_column("Description", style="cyan")

    for u in units:
        table.add_row(f"0x{u.offset:06X}", u.name, f"{u.length:,} B", u.description or "")

    console.print(table)

    if blocks:
        block_table = Table(title=f"Metadata Blocks ({len(blocks)})")
        block_table.add_column("Kind", style="bold yellow")
        block_table.add_column("Offset", style="dim", justify="right")
        block_table.add_column("Length", justify="right")
        block_table.add_column("Source Unit", style="cyan")
        for b in blocks:
            block_table.add_row(b.kind, f"0x{b.offset:06X}", f"{b.length:,} B", b.source_unit or "")
        console.print(block_table)

        # Parse standard metadata blocks to display exact tag and value locations
        std_registry = create_default_standard_registry()
        parsed_fields = []
        for b in blocks:
            parser = std_registry.get_parser(b.kind)
            if parser:
                flds, _, _ = parser.parse(b)
                parsed_fields.extend(flds)

        if parsed_fields:
            field_table = Table(title=f"Metadata Fields & Value Locations ({len(parsed_fields)})")
            field_table.add_column("Field Name", style="bold cyan")
            field_table.add_column("Standard", style="green")
            field_table.add_column("Tag ID", style="dim")
            field_table.add_column("Tag Offset", style="dim", justify="right")
            field_table.add_column("Value Offset", style="bold yellow", justify="right")
            field_table.add_column("Length", justify="right")
            field_table.add_column("Value Preview", style="white")

            for f in parsed_fields:
                tag_off_str = f"0x{f.offset:06X}" if f.offset is not None else "-"
                val_off_str = f"0x{f.value_offset:06X}" if f.value_offset is not None else "-"
                len_str = f"{f.length:,} B" if f.length is not None else "-"
                val_str = str(f.value)
                if len(val_str) > 40:
                    val_str = val_str[:37] + "..."
                field_table.add_row(f.name, f.standard, f.tag_id or "-", tag_off_str, val_off_str, len_str, val_str)

            console.print(field_table)


# -----------------------------------------------------------------------------
# Subcommand: extract
# -----------------------------------------------------------------------------
@cli.command("extract")
@click.argument("target", type=click.Path(exists=True))
@click.option("-o", "--out", "out_dir", default="./extracted", help="Destination folder for extracted artefacts")
@click.option("-a", "--all", "extract_all", is_flag=True, help="Extract all embedded artefacts, metadata blocks, and payloads")
@click.option("-t", "--thumbnail", is_flag=True, help="Extract embedded EXIF thumbnail (IFD1)")
@click.option("-p", "--preview", is_flag=True, help="Extract embedded RAW preview / secondary MPF frames")
@click.option("-c", "--payload", is_flag=True, help="Carve and extract trailing payload archives/executables")
@click.option("-m", "--metadata", is_flag=True, help="Extract raw metadata streams (EXIF, XMP, IPTC, ICC, C2PA)")
@click.option("-x", "--x-pos", "pos_x", type=int, default=None, help="X coordinate for region/pixel extraction")
@click.option("-y", "--y-pos", "pos_y", type=int, default=None, help="Y coordinate for region/pixel extraction")
@click.option("-w", "--width", "crop_width", type=int, default=200, help="Width for region crop extraction (default: 200)")
@click.option("-h", "--height", "crop_height", type=int, default=200, help="Height for region crop extraction (default: 200)")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("--self-audit", is_flag=True, help="Operate in self-audit mode on personal files without an external scope")
def extract(
    target: str,
    out_dir: str,
    extract_all: bool,
    thumbnail: bool,
    preview: bool,
    payload: bool,
    metadata: bool,
    pos_x: Optional[int],
    pos_y: Optional[int],
    crop_width: int,
    crop_height: int,
    scope_path: Optional[str],
    self_audit: bool,
) -> None:
    """Extract embedded thumbnails, previews, payloads, metadata streams, or -x -y image crops."""
    # Scope resolution
    if self_audit:
        auth_scope = AuthorizationScope.create_self_audit_scope()
    elif scope_path:
        try:
            auth_scope = AuthorizationScope.load_from_file(scope_path)
        except ScopeValidationError as e:
            err_console.print(f"[red]Authorization failure (Exit 6): {e}[/red]")
            sys.exit(6)
    else:
        auth_scope = AuthorizationScope.create_self_audit_scope()

    # Default to extract_all if no specific extract flag is selected
    if not (extract_all or thumbnail or preview or payload or metadata or (pos_x is not None and pos_y is not None)):
        extract_all = True

    crop_coords = None
    if pos_x is not None and pos_y is not None:
        crop_coords = {"x": pos_x, "y": pos_y, "width": crop_width, "height": crop_height}

    console.print(f"[bold cyan]matazero Artefact Extractor[/bold cyan] — Target: {target}")
    console.print(f"Destination: [bold]{out_dir}[/bold]\n")

    items = ArtefactExtractor.extract_all(
        file_path=target,
        out_dir=out_dir,
        include_metadata=extract_all or metadata,
        include_thumbnail=extract_all or thumbnail,
        include_preview=extract_all or preview,
        include_payload=extract_all or payload,
        crop_coords=crop_coords,
    )

    if not items:
        console.print("[yellow]No embedded artefacts or payloads found to extract.[/yellow]")
        return

    table = Table(title=f"Extracted Artefacts ({len(items)})")
    table.add_column("Type", style="bold green")
    table.add_column("Offset", style="dim", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("Output File Path", style="cyan")
    table.add_column("SHA-256", style="dim")

    for it in items:
        off_str = f"0x{it.offset:06X}" if it.offset is not None else "-"
        table.add_row(
            it.item_type,
            off_str,
            f"{it.size_bytes:,} B",
            str(it.output_path),
            it.sha256[:16] + "..." if it.sha256 else "-",
        )

    console.print(table)
    console.print(f"\n[green][OK] Successfully extracted {len(items)} artefacts to [bold]{out_dir}[/bold][/green]")


# -----------------------------------------------------------------------------
# Subcommand: audit
# -----------------------------------------------------------------------------
@cli.group()
def audit() -> None:
    """Verify or export the tamper-evident audit log."""
    pass


@audit.command("verify")
@click.argument("audit_file", default="./audit.jsonl", type=click.Path(exists=True))
def audit_verify(audit_file: str) -> None:
    """Cryptographically verify the hash chain of an audit log (GR-2.7)."""
    is_valid, broken_idx, message = verify_audit_chain(audit_file)
    if is_valid:
        console.print(f"[green][OK] {message}[/green]")
    else:
        err_console.print(f"[bold red][X] AUDIT CHAIN COMPROMISED (Exit 7): {message}[/bold red]")
        sys.exit(7)


# -----------------------------------------------------------------------------
# Subcommand: clean
# -----------------------------------------------------------------------------
@cli.command("clean")
@click.argument("target", type=click.Path(exists=True))
@click.option("-o", "--out", "out_path", default=None, type=click.Path(), help="Output path for cleaned file")
@click.option("-c", "--commit", is_flag=True, help="Required to execute modification (dry-run without it per FR-10.9)")
def clean(target: str, out_path: Optional[str], commit: bool) -> None:
    """Losslessly remove metadata in self-audit mode."""
    if not commit:
        console.print("[yellow][DRY RUN] Metadata cleaning simulated. Use --commit to write cleaned output.[/yellow]")
        cleaned, orig_s, clean_s = MetadataCleaner.clean_file(target)
        console.print(f"Original size: {orig_s:,} bytes -> Cleaned size: {clean_s:,} bytes (Saved {orig_s - clean_s:,} bytes)")
        return

    dest = out_path or target
    cleaned, orig_s, clean_s = MetadataCleaner.clean_file(target, output_path=dest)
    console.print(f"[green][OK] Cleaned metadata written to {dest}[/green]")
    console.print(f"  Original size: {orig_s:,} bytes")
    console.print(f"  Cleaned size:  {clean_s:,} bytes (Reduced by {orig_s - clean_s:,} bytes)")


# -----------------------------------------------------------------------------
# Subcommand: corpus
# -----------------------------------------------------------------------------
@cli.group()
def corpus() -> None:
    """Manage and inspect the reference encoder fingerprint corpus."""
    pass


@corpus.command("list")
def corpus_list() -> None:
    """List all registered device and platform encoder profiles."""
    ref_corpus = ReferenceCorpus()
    table = Table(title=f"Reference Encoder Corpus ({len(ref_corpus.entries)} Profiles — v{ref_corpus.version})")
    table.add_column("ID", style="bold cyan")
    table.add_column("Device / Platform Model", style="green")
    table.add_column("Encoder Software", style="yellow")
    table.add_column("Chroma", style="dim")
    table.add_column("Confidence", style="magenta")

    for e in ref_corpus.entries:
        table.add_row(
            e.entry_id,
            e.device_model,
            e.encoder_software,
            e.subsampling,
            f"[{e.confidence.upper()}]",
        )

    console.print(table)


@corpus.command("learn")
@click.argument("target", type=click.Path(exists=True))
@click.option("-i", "--id", "entry_id", required=True, help="Unique profile identifier (e.g. my_custom_device)")
@click.option("-m", "--model", required=True, help="Device or camera model description")
@click.option("-e", "--encoder", default="Custom JPEG Pipeline", help="Encoder software description")
def corpus_learn(target: str, entry_id: str, model: str, encoder: str) -> None:
    """Learn and register a new camera fingerprint from a reference JPEG."""
    p = Path(target)
    reader = BoundedReader(p)
    detected = FormatDetector.detect(reader)
    if detected.format_name != "JPEG":
        err_console.print(f"[red]Corpus learning currently requires JPEG reference images (detected: {detected.format_name})[/red]")
        sys.exit(3)

    registry = create_default_container_registry()
    container_reader = registry.get_reader("JPEG")
    units, blocks, diags = container_reader.read(reader)

    dqt_tables = []
    subsampling_info = None
    for u in units:
        if u.name == "DQT" and u.payload:
            dqt_tables.extend(DqtExtractor.extract_from_dqt_payload(u.payload))
        elif u.name.startswith("SOF") and u.payload:
            subsampling_info = SubsamplingExtractor.extract_from_sof_payload(u.payload)

    if not dqt_tables:
        err_console.print("[red]No DQT Quantization Tables found in reference image[/red]")
        sys.exit(1)

    lum_sample = dqt_tables[0].values
    seq = SegmentOrderExtractor.extract_sequence(units)
    ss_str = subsampling_info.notation if subsampling_info else "4:2:0"

    entry = CorpusEntry(
        entry_id=entry_id,
        device_model=model,
        encoder_software=encoder,
        processing_chain="Learned reference profile (User Corpus)",
        subsampling=ss_str,
        dqt_luminance_sample=lum_sample,
        segment_prefix=seq[:6],
        confidence="indicative",
    )

    ref_corpus = ReferenceCorpus()
    ref_corpus.add_user_entry(entry)

    console.print(f"[green][OK] Fingerprint profile [bold]{entry_id}[/bold] learned and saved to user corpus![/green]")
    console.print(f"  Model:       {model}")
    console.print(f"  Encoder:     {encoder}")
    console.print(f"  Subsampling: {ss_str}")
    console.print(f"  DQT Samples: {len(lum_sample)} values")


# -----------------------------------------------------------------------------
# Subcommand: completion
# -----------------------------------------------------------------------------
@cli.command("completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell: str) -> None:
    """Generate shell completion scripts (bash, zsh, fish)."""
    if shell == "bash":
        console.print('# bash completion for matazero\neval "$(_MATAZERO_COMPLETE=bash_source matazero)"')
    elif shell == "zsh":
        console.print('# zsh completion for matazero\neval "$(_MATAZERO_COMPLETE=zsh_source matazero)"')
    elif shell == "fish":
        console.print('# fish completion for matazero\neval (env _MATAZERO_COMPLETE=fish_source matazero)')


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
