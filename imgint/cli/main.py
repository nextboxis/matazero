"""Command-line interface for imgint per SRD §3.10 and SRS §3.1."""

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
from imgint.cli.commands._utils import resolve_scope, ExitCode
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

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)


class DefaultGroup(click.Group):
    """Custom Click Group that defaults to a specified command (analyze) when invoked directly with image targets or options."""

    def __init__(self, *args, **kwargs):
        self.default_cmd_name = kwargs.pop("default", None)
        super().__init__(*args, **kwargs)

    def parse_args(self, ctx, args):
        if not args:
            return super().parse_args(ctx, args)
        if args[0] in ("-h", "--help", "--version"):
            return super().parse_args(ctx, args)
        if args[0] in self.commands:
            return super().parse_args(ctx, args)
        if self.default_cmd_name:
            args = [self.default_cmd_name] + list(args)
        return super().parse_args(ctx, args)


@click.group(cls=DefaultGroup, default="analyze")
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
        sys.exit(ExitCode.SCOPE_ERROR)


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
@click.option("--ollama", "ollama_model", default=None, help="Enable local Ollama vision inspection in Tier 7 with specified model (e.g. llama3.2-vision, moondream)")
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
    ollama_model: Optional[str],
    jobs: int,
    out_file: Optional[str],
) -> None:
    """Run 7 extraction tiers over evidence files."""
    # Scope resolution
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=True, err_console=err_console)

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
        ollama_model=ollama_model,
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
                        sys.exit(ExitCode.CUSTODY_ERROR)
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
                    sys.exit(ExitCode.CUSTODY_ERROR)
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
# Subcommand: scan (1-Command Smart Evidence Triage & Case Dossier Generator)
# -----------------------------------------------------------------------------
@cli.command("scan")
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("-o", "--out", "out_dossier", default=None, type=click.Path(), help="Output path for standalone HTML Case Dossier (e.g. case_dossier.html)")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, default=True, help="Operate in self-audit mode on personal files without an external scope")
@click.option("-r", "--recursive", is_flag=True, default=True, help="Recursively search directory targets for images (default: True)")
@click.option("--glob", "glob_pattern", default=None, help="Glob pattern to filter files (e.g. '*.jpg', '*.png')")
@click.option("-e", "--ela", is_flag=True, help="Enable Error Level Analysis in Tier 6")
@click.option("-c", "--carve", is_flag=True, help="Automatically carve trailing archives or payloads")
@click.option("-j", "--jobs", default=4, type=int, help="Number of concurrent worker threads (default: 4)")
@click.option("--title", "case_title", default="matazero Forensic Evidence Triage Dossier", help="Title for the generated Case Dossier")
def scan(
    targets: List[str],
    out_dossier: Optional[str],
    scope_path: Optional[str],
    self_audit: bool,
    recursive: bool,
    glob_pattern: Optional[str],
    ela: bool,
    carve: bool,
    jobs: int,
    case_title: str,
) -> None:
    """Smart 1-command evidence auto-triage with live progress and HTML dossier generation."""
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)
    resolved_targets = _expand_file_targets(targets, recursive=recursive, glob_pattern=glob_pattern)
    if not resolved_targets:
        err_console.print("[yellow]No matching image evidence files found to scan.[/yellow]")
        return

    pipeline = AnalysisPipeline(
        scope=auth_scope,
        allow_network=False,
        enable_ela=ela,
        selected_tiers={1, 2, 3, 4, 5, 6, 7},
    )

    records: List[AnalysisRecord] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"[cyan]Triaging {len(resolved_targets)} evidence file(s)...[/cyan]", total=len(resolved_targets))

        def _process(p: Path):
            try:
                rec = pipeline.analyze_file(p)
                if carve and rec.structural_units:
                    reader = BoundedReader(p)
                    PayloadCarver.carve_trailing_payload(reader, rec.structural_units, "./evidence_store/carved")
                return rec
            except Exception:
                return None

        if jobs > 1 and len(resolved_targets) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
                futures = {executor.submit(_process, t): t for t in resolved_targets}
                for fut in concurrent.futures.as_completed(futures):
                    rec = fut.result()
                    if rec:
                        records.append(rec)
                    progress.advance(task)
        else:
            for t in resolved_targets:
                rec = _process(t)
                if rec:
                    records.append(rec)
                progress.advance(task)

    if not records:
        console.print("[red]No records could be analyzed.[/red]")
        return

    # Triage Categorization Stats
    authentic = [r for r in records if "AUTHENTIC" in (r.authenticity_verdict or {}).get("rating", "")]
    tampered = [r for r in records if "TAMPERED" in (r.authenticity_verdict or {}).get("rating", "")]
    synthetic = [r for r in records if "SYNTHETIC" in (r.authenticity_verdict or {}).get("rating", "") or "AI" in (r.authenticity_verdict or {}).get("rating", "")]
    inconclusive = [r for r in records if r not in authentic and r not in tampered and r not in synthetic]

    table = Table(title=f"matazero Smart Triage Summary ({len(records)} Files)", border_style="cyan")
    table.add_column("Category", style="bold white")
    table.add_column("Count", justify="right", style="bold")
    table.add_column("Percentage", justify="right", style="dim")
    table.add_column("Indicators", style="dim")

    tot = len(records)
    table.add_row("[green]Authentic Hardware Capture[/green]", f"{len(authentic):,}", f"{len(authentic)/tot*100:.1f}%", "Hardware DQT/DHT matches known camera corpus")
    table.add_row("[red]Tampered / Spliced / Payload[/red]", f"{len(tampered):,}", f"{len(tampered)/tot*100:.1f}%", "Trailing data past EOI, ELA variance, ghost recompression")
    table.add_row("[magenta]AI Generated / Synthetic[/magenta]", f"{len(synthetic):,}", f"{len(synthetic)/tot*100:.1f}%", "Absence of CFA Bayer periodicity, AI generator DQT")
    table.add_row("[yellow]Stripped / Inconclusive[/yellow]", f"{len(inconclusive):,}", f"{len(inconclusive)/tot*100:.1f}%", "Social media sanitized, missing metadata")

    console.print(table)

    # Generate HTML Case Dossier
    dossier_target = out_dossier or "case_dossier.html"
    CaseDossierGenerator.generate_html(
        records=records,
        case_title=case_title,
        output_path=dossier_target,
    )
    console.print(f"\n[bold green][OK] Interactive Dark-Mode HTML Case Dossier generated:[/bold green] [cyan]{dossier_target}[/cyan]")


# -----------------------------------------------------------------------------
# Subcommand: locate (Forensic Geolocation & Chronolocation Intelligence)
# -----------------------------------------------------------------------------
@cli.command("locate")
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
    # Initialize custom SQLite database if explicitly passed
    if sqlite_path:
        NaturalEarthDB.get_instance(db_path=sqlite_path)

    # Scope resolution
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)

    resolved_targets = _expand_file_targets(targets, recursive=recursive, glob_pattern=glob_pattern)
    if not resolved_targets:
        err_console.print("[yellow]No matching image files found to locate.[/yellow]")
        return

    # Resolve IP Geolocation if provided
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
            # Facility proximity (airports, seaports)
            try:
                fac_ctx = GeoLocator.get_facility_context(lat, lon)
                if fac_ctx.get("has_facility_proximity"):
                    point_record["facility_proximity"] = fac_ctx
            except Exception:
                pass

            # Optical viewing cone & camera sightline
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

    else:  # table
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
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)

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
        sys.exit(ExitCode.CUSTODY_ERROR)


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
# Subcommand: geo (Geospatial Dataset & Ingestion Management)
# -----------------------------------------------------------------------------
@cli.group("geo")
def geo_group() -> None:
    """Manage offline geospatial datasets, spatial indexing, and NDJSON ingestion."""
    pass


@geo_group.command("stats")
def geo_stats() -> None:
    """Display statistics and indexing status for the offline geospatial databases."""
    places = GeoLocator.load_offline_database()
    ne_db = NaturalEarthDB.get_instance()

    table = Table(title="matazero Geospatial Intelligence Database Status", border_style="cyan")
    table.add_column("Component", style="bold white")
    table.add_column("Status / Count", style="bold green")
    table.add_column("Details", style="dim")

    table.add_row(
        "In-Memory Offline Places",
        f"{len(places):,} places",
        "Indexed via 3D SpatialKDTree (< 30 microseconds/query)"
    )
    table.add_row(
        "Natural Earth SQLite DB",
        "[green]CONNECTED[/green]" if ne_db.is_available else "[yellow]NOT CONNECTED[/yellow]",
        str(ne_db.db_path) if ne_db.is_available else "Not located at default paths"
    )
    console.print(table)


@geo_group.command("ingest")
@click.argument("ndjson_file", type=click.Path(exists=True))
@click.option("-t", "--target", "target_path", default=None, type=click.Path(), help="Target JSON database path")
@click.option("-l", "--limit", "record_limit", default=None, type=int, help="Maximum number of records to ingest")
def geo_ingest(ndjson_file: str, target_path: Optional[str], record_limit: Optional[int]) -> None:
    """Ingest OpenStreetMap or Overture Maps NDJSON files into the offline database."""
    default_target = target_path or str(Path(__file__).parent.parent / "core" / "data" / "geonames_offline.json")
    with console.status(f"[cyan]Ingesting places from {ndjson_file}...[/cyan]"):
        added, total = NDJSONGeoIngester.ingest_and_merge(
            ndjson_path=ndjson_file,
            target_json_path=default_target,
            max_records=record_limit
        )

    console.print(f"[green][OK] Successfully ingested {added:,} new places into {default_target} (Total: {total:,} places)[/green]")


# -----------------------------------------------------------------------------
# Subcommand: diff (Forensic Differential Image Analysis)
# -----------------------------------------------------------------------------
@cli.command("diff")
@click.argument("target_a", type=click.Path(exists=True))
@click.argument("target_b", type=click.Path(exists=True))
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.option("-o", "--out", "out_file", default=None, type=click.Path(), help="Write diff report to file")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode without an external scope")
def diff(
    target_a: str,
    target_b: str,
    out_fmt: str,
    out_file: Optional[str],
    scope_path: Optional[str],
    self_audit: bool,
) -> None:
    """Forensic comparison between two images (structure, metadata, DQT, and pixels)."""
    # Scope resolution
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)

    pipeline = AnalysisPipeline(scope=auth_scope, selected_tiers={1, 2, 3, 4, 5, 6, 7})
    result = ForensicComparator.compare(target_a, target_b, pipeline=pipeline)

    if out_fmt == "json":
        rendered = DiffRenderer.render_json(result)
        if out_file:
            Path(out_file).write_text(rendered, encoding="utf-8")
            console.print(f"[green][OK] Diff report written to {out_file}[/green]")
        else:
            print(rendered)
    else:
        DiffRenderer.render_terminal(result, console)
        if out_file:
            rendered = DiffRenderer.render_json(result)
            Path(out_file).write_text(rendered, encoding="utf-8")
            console.print(f"\n[green][OK] Full diff data written to {out_file}[/green]")


# -----------------------------------------------------------------------------
# Subcommand: stego (Deep Steganography & Bitplane Slicer)
# -----------------------------------------------------------------------------
@cli.command("stego")
@click.argument("target", type=click.Path(exists=True))
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.option("-o", "--out", "out_file", default=None, type=click.Path(), help="Write analysis report to file")
@click.option("--save-bitplanes", "save_bp_dir", default=None, type=click.Path(), help="Directory to save extracted bitplane PNG images")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode without an external scope")
def stego(
    target: str,
    out_fmt: str,
    out_file: Optional[str],
    save_bp_dir: Optional[str],
    scope_path: Optional[str],
    self_audit: bool,
) -> None:
    """Deep Steganography, Multi-Channel Bitplane Slicing, and Chi-Square PoV Inspection."""
    # Scope resolution
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)

    result = StegoInspector.inspect(target, save_bitplanes_dir=save_bp_dir)

    if out_fmt == "json":
        rendered = StegoRenderer.render_json(result)
        if out_file:
            Path(out_file).write_text(rendered, encoding="utf-8")
            console.print(f"[green][OK] Stego report written to {out_file}[/green]")
        else:
            print(rendered)
    else:
        StegoRenderer.render_terminal(result, console)
        if out_file:
            rendered = StegoRenderer.render_json(result)
            Path(out_file).write_text(rendered, encoding="utf-8")
            console.print(f"\n[green][OK] Full stego data written to {out_file}[/green]")


# -----------------------------------------------------------------------------
# Subcommand: timeline (Forensic Chronology & Clock Drift Reconstruction)
# -----------------------------------------------------------------------------
@cli.command("timeline")
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "json", "csv", "plaso"]), default="table", help="Output format")
@click.option("-o", "--out", "out_file", default=None, type=click.Path(), help="Write timeline to file")
@click.option("-r", "--recursive", is_flag=True, help="Recursively search directory targets for images")
@click.option("--glob", "glob_pattern", default=None, help="Glob pattern to filter files (e.g. '*.jpg')")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode without an external scope")
def timeline(
    targets: List[str],
    out_fmt: str,
    out_file: Optional[str],
    recursive: bool,
    glob_pattern: Optional[str],
    scope_path: Optional[str],
    self_audit: bool,
) -> None:
    """Reconstruct multi-asset chronological timelines and estimate camera clock drift."""
    # Scope resolution
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)

    resolved_targets = _expand_file_targets(targets, recursive=recursive, glob_pattern=glob_pattern)
    if not resolved_targets:
        err_console.print("[yellow]No matching image evidence files found to reconstruct timeline.[/yellow]")
        return

    pipeline = AnalysisPipeline(scope=auth_scope, selected_tiers={1, 5, 6})
    report = TimelineReconstructor.reconstruct(resolved_targets, pipeline=pipeline)

    if out_fmt == "json":
        rendered = TimelineExporter.to_json(report)
    elif out_fmt in ("csv", "plaso"):
        rendered = TimelineExporter.to_plaso_csv(report)
    else:  # table
        TimelineExporter.render_terminal(report, console)
        rendered = ""

    if rendered:
        if out_file:
            Path(out_file).write_text(rendered, encoding="utf-8")
            console.print(f"[green][OK] Timeline written to {out_file}[/green]")
        else:
            print(rendered)
    elif out_file:
        Path(out_file).write_text(TimelineExporter.to_json(report), encoding="utf-8")
        console.print(f"\n[green][OK] Timeline data written to {out_file}[/green]")


# -----------------------------------------------------------------------------
# Subcommand: motion (Motion & Live Photo Video Carving)
# -----------------------------------------------------------------------------
@cli.command("motion")
@click.argument("target", type=click.Path(exists=True))
@click.option("-c", "--carve", is_flag=True, help="Carve embedded video stream to disk")
@click.option("-o", "--out", "out_path", default=None, type=click.Path(), help="Output path/directory for carved video")
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
def motion(
    target: str,
    carve: bool,
    out_path: Optional[str],
    out_fmt: str,
) -> None:
    """Detect and carve embedded MP4/HEVC video streams from Samsung/Pixel/Apple motion photos."""
    if carve:
        info = MotionPhotoCarver.carve(target, output_file=out_path if out_path and out_path.endswith((".mp4", ".mov")) else None, output_dir=out_path)
    else:
        info = MotionPhotoDetector.detect(target)

    if out_fmt == "json":
        print(MotionPhotoRenderer.render_json(info))
    else:
        MotionPhotoRenderer.render_terminal(info, console)


# -----------------------------------------------------------------------------
# Subcommand: cluster (Multi-Image Fleet & Anomaly Triage)
# -----------------------------------------------------------------------------
@cli.command("cluster")
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--by", "strategy", type=click.Choice(["camera", "dqt", "geo", "visual"]), default="camera", help="Clustering dimension (default: camera)")
@click.option("--radius", "geo_radius", default=5.0, type=float, help="Geospatial clustering radius in km (default: 5.0)")
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.option("-o", "--out", "out_file", default=None, type=click.Path(), help="Write clustering report to file")
@click.option("-r", "--recursive", is_flag=True, help="Recursively search directory targets for images")
@click.option("--glob", "glob_pattern", default=None, help="Glob pattern to filter files (e.g. '*.jpg')")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode without an external scope")
def cluster(
    targets: List[str],
    strategy: str,
    geo_radius: float,
    out_fmt: str,
    out_file: Optional[str],
    recursive: bool,
    glob_pattern: Optional[str],
    scope_path: Optional[str],
    self_audit: bool,
) -> None:
    """Group evidence files by camera fleet, DQT tables, GPS proximity, or visual similarity."""
    # Scope resolution
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)

    resolved_targets = _expand_file_targets(targets, recursive=recursive, glob_pattern=glob_pattern)
    if not resolved_targets:
        err_console.print("[yellow]No matching image evidence files found to cluster.[/yellow]")
        return

    pipeline = AnalysisPipeline(scope=auth_scope, selected_tiers={1, 2, 4, 5, 6})
    report = ClusterEngine.cluster(resolved_targets, strategy=strategy, geo_radius_km=geo_radius, pipeline=pipeline)

    if out_fmt == "json":
        rendered = ClusterRenderer.render_json(report)
        if out_file:
            Path(out_file).write_text(rendered, encoding="utf-8")
            console.print(f"[green][OK] Cluster data written to {out_file}[/green]")
        else:
            print(rendered)
    else:
        ClusterRenderer.render_terminal(report, console)
        if out_file:
            Path(out_file).write_text(ClusterRenderer.render_json(report), encoding="utf-8")
            console.print(f"\n[green][OK] Cluster data written to {out_file}[/green]")


# -----------------------------------------------------------------------------
# Subcommand: export (Database & Threat Intelligence Bundles)
# -----------------------------------------------------------------------------
@cli.group("export")
def export_group() -> None:
    """Export forensic findings to SQLite database or STIX 2.1 Threat Intel bundles."""
    pass


@export_group.command("sqlite")
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("-o", "--out", "db_path", default="./evidence_vault.db", type=click.Path(), help="Destination SQLite database file (default: ./evidence_vault.db)")
@click.option("-r", "--recursive", is_flag=True, help="Recursively search directory targets for images")
@click.option("--glob", "glob_pattern", default=None, help="Glob pattern to filter files")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode")
def export_sqlite(
    targets: List[str],
    db_path: str,
    recursive: bool,
    glob_pattern: Optional[str],
    scope_path: Optional[str],
    self_audit: bool,
) -> None:
    """Index analysis records into a structured, queryable SQLite relational database."""
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)
    resolved_targets = _expand_file_targets(targets, recursive=recursive, glob_pattern=glob_pattern)
    if not resolved_targets:
        err_console.print("[yellow]No matching image files to export.[/yellow]")
        return

    pipeline = AnalysisPipeline(scope=auth_scope, selected_tiers={1, 2, 3, 4, 5, 6, 7})
    records = [pipeline.analyze_file(t) for t in resolved_targets]
    out_db = SqliteExporter.export(records, db_path)
    console.print(f"[green][OK] Successfully indexed {len(records)} evidence images into SQLite database: [bold]{out_db}[/bold][/green]")


@export_group.command("stix")
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("-o", "--out", "out_file", default=None, type=click.Path(), help="Destination STIX 2.1 JSON file")
@click.option("-r", "--recursive", is_flag=True, help="Recursively search directory targets for images")
@click.option("--glob", "glob_pattern", default=None, help="Glob pattern to filter files")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode")
def export_stix(
    targets: List[str],
    out_file: Optional[str],
    recursive: bool,
    glob_pattern: Optional[str],
    scope_path: Optional[str],
    self_audit: bool,
) -> None:
    """Generate STIX 2.1 Threat Intelligence Bundle with Cyber Observable and Indicator Objects."""
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)
    resolved_targets = _expand_file_targets(targets, recursive=recursive, glob_pattern=glob_pattern)
    if not resolved_targets:
        err_console.print("[yellow]No matching image files to export.[/yellow]")
        return

    pipeline = AnalysisPipeline(scope=auth_scope, selected_tiers={1, 2, 3, 4, 5, 6, 7})
    records = [pipeline.analyze_file(t) for t in resolved_targets]
    bundle = StixExporter.export(records)
    rendered = json.dumps(bundle, indent=2)

    if out_file:
        Path(out_file).write_text(rendered, encoding="utf-8")
        console.print(f"[green][OK] STIX 2.1 Threat Intel Bundle ({len(bundle['objects'])} objects) written to [bold]{out_file}[/bold][/green]")
    else:
        print(rendered)


# -----------------------------------------------------------------------------
# Subcommand: skill (Microkernel Skills & Extensible Plugins)
# -----------------------------------------------------------------------------
@cli.group("skill")
def skill_group() -> None:
    """Manage and inspect dynamically loaded forensic skills and plugins."""
    pass


@skill_group.command("list")
def skill_list() -> None:
    """List all currently discovered and loaded forensic skills."""
    registry = SkillRegistry.get_default()
    skills = registry.list_skills()

    if not skills:
        console.print("[dim]No external skills discovered in ~/.matazero/skills or ./.matazero/skills.[/dim]")
        return

    table = Table(title=f"Discovered Forensic Skills ({len(skills)} Loaded)", border_style="cyan")
    table.add_column("Skill ID", style="bold cyan")
    table.add_column("Name", style="white")
    table.add_column("Version", style="green")
    table.add_column("Tier", justify="center", style="yellow")
    table.add_column("Formats", style="magenta")
    table.add_column("Description", style="dim")

    for s in skills:
        table.add_row(
            s.id,
            s.name,
            s.version,
            str(s.target_tier),
            ", ".join(s.supported_formats),
            s.description,
        )

    console.print(table)


@skill_group.command("info")
@click.argument("skill_id")
def skill_info(skill_id: str) -> None:
    """Display detailed manifest and metadata for a specific forensic skill."""
    registry = SkillRegistry.get_default()
    skill = registry.get_skill(skill_id)

    if not skill:
        err_console.print(f"[red]Skill '{skill_id}' not found in registry.[/red]")
        return

    panel_content = Text()
    panel_content.append(f"Skill ID:        ", style="dim")
    panel_content.append(f"{skill.id}\n", style="bold cyan")
    panel_content.append(f"Name:            ", style="dim")
    panel_content.append(f"{skill.name}\n", style="bold white")
    panel_content.append(f"Version:         ", style="dim")
    panel_content.append(f"{skill.version}\n", style="green")
    panel_content.append(f"Execution Tier:  ", style="dim")
    panel_content.append(f"Tier {skill.target_tier}\n", style="yellow")
    panel_content.append(f"Target Formats:  ", style="dim")
    panel_content.append(f"{', '.join(skill.supported_formats)}\n", style="magenta")
    panel_content.append(f"Pixel Decode:    ", style="dim")
    panel_content.append(f"{'Required' if skill.requires_decode else 'No'}\n", style="white")
    panel_content.append(f"\nDescription:\n", style="bold dim")
    panel_content.append(f"{skill.description or 'No description provided.'}\n", style="white")
    console.print(Panel(panel_content, title=f"Skill: {skill.name}", border_style="cyan"))

# -----------------------------------------------------------------------------
# Subcommand: ask (Interactive Local AI Visual Interrogation)
# -----------------------------------------------------------------------------
@cli.command("ask")
@click.argument("target", type=click.Path(exists=True))
@click.argument("question", required=False, default=None)
@click.option("--deep", "--details", "deep_mode", is_flag=True, help="Perform an exhaustive, deep forensic visual analysis")
@click.option("-m", "--model", "model_name", default=None, help="Local Ollama vision model (default: auto-detected, e.g. llama3.2-vision, moondream, llava)")
@click.option("--host", default="http://localhost:11434", help="Ollama server host (default: http://localhost:11434)")
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
def ask(
    target: str,
    question: Optional[str],
    deep_mode: bool,
    model_name: Optional[str],
    host: str,
    out_fmt: str,
) -> None:
    """Interrogate an evidence image using your local Ollama vision model."""
    client = OllamaClient(host=host)
    if not client.is_available():
        err_console.print(
            f"[bold red][X] Cannot connect to Ollama at {host}[/bold red]\n"
            "[dim]Start the local Ollama daemon by running: [bold green]ollama serve[/bold green][/dim]"
        )
        sys.exit(1)

    selected_model = model_name or client.get_default_vision_model()
    if not selected_model:
        err_console.print(
            "[bold red][X] No vision models found in local Ollama.[/bold red]\n"
            "[dim]Pull a vision model with: [bold cyan]ollama pull llama3.2-vision[/bold cyan] or [bold cyan]ollama pull llava[/bold cyan][/dim]"
        )
        sys.exit(1)

    if not question:
        if deep_mode:
            prompt_text = "Perform an exhaustive forensic visual examination of this image. Detail all visible objects, background setting, text/numbers, lighting/shadow consistency, and any suspicious anomalies."
            display_question = "Exhaustive Forensic Visual Examination (--deep)"
        else:
            prompt_text = "Describe this image in detail, noting visible subjects, objects, setting, and any visible text."
            display_question = "General Visual Description"
    else:
        if deep_mode:
            prompt_text = f"Perform an exhaustive, deeply detailed forensic examination to answer the following:\n{question}\n\nProvide granular observations on visual features, spatial positioning, text, lighting consistency, and any anomalies."
            display_question = f"{question} [Deep Mode]"
        else:
            prompt_text = question
            display_question = question

    with console.status(f"[cyan]Analyzing image with {selected_model}...[/cyan]"):
        res = client.generate(
            model=selected_model,
            prompt=prompt_text,
            image_path_or_bytes=target,
        )

    if res.get("error"):
        err_console.print(f"[bold red]Ollama error:[/bold red] {res['error']}")
        sys.exit(1)

    resp_text = res.get("response", "").strip()

    if out_fmt == "json":
        print(json.dumps({
            "target": str(Path(target).resolve()),
            "model": selected_model,
            "question": display_question,
            "deep_mode": deep_mode,
            "response": resp_text,
        }, indent=2))
    else:
        OllamaRenderer.render_ask_response(target, display_question, selected_model, resp_text, console)


# -----------------------------------------------------------------------------
# Subcommand: model (Local Model Discovery & Management)
# -----------------------------------------------------------------------------
@cli.group("model")
def model_group() -> None:
    """Manage and inspect local vision models available in Ollama."""
    pass


@model_group.command("list")
@click.option("--host", default="http://localhost:11434", help="Ollama server host")
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
def model_list(host: str, out_fmt: str) -> None:
    """Discover and list installed models in local Ollama instance."""
    client = OllamaClient(host=host)
    is_online = client.is_available()
    models = client.list_models() if is_online else []

    if out_fmt == "json":
        print(json.dumps({
            "ollama_online": is_online,
            "host": host,
            "model_count": len(models),
            "models": models,
        }, indent=2))
    else:
        OllamaRenderer.render_models_table(models, is_online, console)


# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# Subcommand: doctor (System Environment & Diagnostic Suite)
# -----------------------------------------------------------------------------
@cli.command("doctor")
def doctor() -> None:
    """Run system health and diagnostic checks across all forensic engines."""
    DiagnosticRunner.run_all_checks(console)


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
