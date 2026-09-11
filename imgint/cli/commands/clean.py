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

@click.command("clean")
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


