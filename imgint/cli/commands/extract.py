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

@click.command("extract")
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
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)

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


