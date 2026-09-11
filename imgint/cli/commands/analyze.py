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

import concurrent.futures
from imgint import __version__
from imgint.cli.commands._utils import (
    resolve_scope,
    ExitCode,
    expand_targets,
    _expand_file_targets,
    _apply_record_filter,
    _apply_field_selection,
    IMAGE_EXTENSIONS,
)
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

@click.command("analyze")
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
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=True, err_console=err_console)

    evidence_store = EvidenceStore(store_path) if not self_audit else None
    audit_logger = AuditLogger(audit_path, scope_id=auth_scope.case_id) if not self_audit else None

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
    else:
        if out_file or out_fmt == "text":
            rendered = "\n\n".join(ReportRenderer.render_report(r) for r in records)
        else:
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
        sys.exit(4)


