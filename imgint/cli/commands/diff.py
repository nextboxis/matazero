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

@click.command("diff")
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


