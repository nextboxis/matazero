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

@click.command("ask")
@click.argument("target", type=click.Path(exists=True))
@click.argument("question", required=False, default=None)
@click.option("--deep", "--details", "deep_mode", is_flag=True, help="Perform an exhaustive, deep forensic visual analysis")
@click.option("-m", "--model", "model_name", default=None, help="Local Ollama vision model (default: auto-detected, e.g. llama3.2-vision, moondream, llava)")
@click.option("--host", default="http://localhost:11434", help="Ollama server host (default: http://localhost:11434)")
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
def ask(
    target: str,
    question: Optional[str],
    deep_mode: bool,
    model_name: Optional[str],
    host: str,
    out_fmt: str,
) -> None:
    """Interrogate an evidence image using your local Ollama vision model."""
    client = OllamaClient(host=host)
    if not client.is_available():
        err_console.print(
            f"[bold red][X] Cannot connect to Ollama at {host}[/bold red]\n"
            "[dim]Start the local Ollama daemon by running: [bold green]ollama serve[/bold green][/dim]"
        )
        sys.exit(1)

    selected_model = model_name or client.get_default_vision_model()
    if not selected_model:
        err_console.print(
            "[bold red][X] No vision models found in local Ollama.[/bold red]\n"
            "[dim]Pull a vision model with: [bold cyan]ollama pull llama3.2-vision[/bold cyan] or [bold cyan]ollama pull llava[/bold cyan][/dim]"
        )
        sys.exit(1)

    if not question:
        if deep_mode:
            prompt_text = "Perform an exhaustive forensic visual examination of this image. Detail all visible objects, background setting, text/numbers, lighting/shadow consistency, and any suspicious anomalies."
            display_question = "Exhaustive Forensic Visual Examination (--deep)"
        else:
            prompt_text = "Describe this image in detail, noting visible subjects, objects, setting, and any visible text."
            display_question = "General Visual Description"
    else:
        if deep_mode:
            prompt_text = f"Perform an exhaustive, deeply detailed forensic examination to answer the following:\n{question}\n\nProvide granular observations on visual features, spatial positioning, text, lighting consistency, and any anomalies."
            display_question = f"{question} [Deep Mode]"
        else:
            prompt_text = question
            display_question = question

    with console.status(f"[cyan]Analyzing image with {selected_model}...[/cyan]"):
        res = client.generate(
            model=selected_model,
            prompt=prompt_text,
            image_path_or_bytes=target,
        )

    if res.get("error"):
        err_console.print(f"[bold red]Ollama error:[/bold red] {res['error']}")
        sys.exit(1)

    resp_text = res.get("response", "").strip()

    if out_fmt == "json":
        print(json.dumps({
            "target": str(Path(target).resolve()),
            "model": selected_model,
            "question": display_question,
            "deep_mode": deep_mode,
            "response": resp_text,
        }, indent=2))
    else:
        OllamaRenderer.render_ask_response(target, display_question, selected_model, resp_text, console)


