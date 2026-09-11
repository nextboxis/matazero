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

@click.command("probe")
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


