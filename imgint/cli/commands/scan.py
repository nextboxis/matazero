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
from imgint.cli.commands._utils import resolve_scope, ExitCode, expand_targets, IMAGE_EXTENSIONS
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

@click.command("scan")
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

    dossier_target = out_dossier or "case_dossier.html"
    CaseDossierGenerator.generate_html(
        records=records,
        case_title=case_title,
        output_path=dossier_target,
    )
    console.print(f"\n[bold green][OK] Interactive Dark-Mode HTML Case Dossier generated:[/bold green] [cyan]{dossier_target}[/cyan]")


