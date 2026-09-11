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

@click.group()
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


