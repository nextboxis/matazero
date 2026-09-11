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

@click.group("geo")
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


