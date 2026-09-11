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
from imgint.cli.commands._utils import resolve_scope, ExitCode, expand_targets, _expand_file_targets, IMAGE_EXTENSIONS
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

@click.group("export")
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


