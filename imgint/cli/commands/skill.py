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

@click.group("skill")
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

