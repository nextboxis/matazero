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
def scope() -> None:
    """Create, validate, or display an authorization scope."""
    pass


@scope.command("create")
@click.option("-c", "--case", "case_id", required=True, help="Case identifier (e.g. CASE-2026-001)")
@click.option("-p", "--purpose", required=True, help="Investigation purpose")
@click.option("-l", "--legal-basis", required=True, help="Lawful basis (e.g. Subpoena, Consent, Legitimate Interest)")
@click.option("-a", "--authorising-party", required=True, help="Authorising authority / lead investigator")
@click.option("-d", "--days", default=30, type=int, help="Validity period in days (default: 30)")
@click.option("-o", "--out", "out_path", required=True, type=click.Path(), help="Output path for scope JSON file")
@click.option("-k", "--secret", default=None, help="Optional HMAC secret key for cryptographic signing")
def scope_create(case_id: str, purpose: str, legal_basis: str, authorising_party: str, days: int, out_path: str, secret: Optional[str]) -> None:
    """Create a new signed authorization scope file."""
    exp_date = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    auth_scope = AuthorizationScope(
        case_id=case_id,
        purpose=purpose,
        legal_basis=legal_basis,
        authorising_party=authorising_party,
        data_subject_categories=["Image Source Files"],
        permitted_operations=["tier1", "tier2", "tier3", "tier4", "tier5", "tier6", "tier7"],
        retention_period_days=days,
        expiry_date=exp_date,
    )
    auth_scope.save_to_file(out_path, secret_key=secret)
    console.print(f"[green][OK][/green] Authorization scope created at [bold]{out_path}[/bold]")
    console.print(f"  Case ID:     {case_id}")
    console.print(f"  Expiry:      {exp_date}")
    console.print(f"  Scope Hash:  {auth_scope.scope_hash}")
    if secret:
        console.print(f"  Signature:   {auth_scope.signature}")


@scope.command("validate")
@click.argument("scope_file", type=click.Path(exists=True))
@click.option("-k", "--secret", default=None, help="Optional HMAC secret key for signature verification")
def scope_validate(scope_file: str, secret: Optional[str]) -> None:
    """Validate the integrity and expiration status of a scope file."""
    try:
        s = AuthorizationScope.load_from_file(scope_file, secret_key=secret)
        console.print(f"[green][OK] Scope is VALID[/green]")
        console.print(f"  Case ID:     {s.case_id}")
        console.print(f"  Purpose:     {s.purpose}")
        console.print(f"  Legal Basis: {s.legal_basis}")
        console.print(f"  Expires:     {s.expiry_date}")
        console.print(f"  Scope Hash:  {s.scope_hash}")
    except ScopeValidationError as e:
        err_console.print(f"[red][X] Scope INVALID: {e}[/red]")
        sys.exit(ExitCode.SCOPE_ERROR)


_expand_file_targets = expand_targets


def _apply_record_filter(rec, filter_expr: Optional[str]) -> bool:
    """Applies high-level forensic query filters to analysis records."""
    if not filter_expr:
        return True
    expr = filter_expr.strip().lower()
    if expr in ("has_gps", "gps"):
        return any(f.name == "gps_coordinates_claimed" for f in rec.findings)
    if expr in ("has_payload", "payload", "carve"):
        return any(f.name == "trailing_data_detected" for f in rec.findings)
    if expr in ("authentic=false", "modified", "tampered"):
        return any(f.name == "authenticity_verdict" and f.value.get("is_authentic") is False for f in rec.findings)
    if expr in ("authentic=true", "authentic"):
        return any(f.name == "authenticity_verdict" and f.value.get("is_authentic") is True for f in rec.findings)
    if expr.startswith("tier="):
        try:
            t_num = int(expr.split("=")[1])
            return any(f.tier == t_num for f in rec.findings)
        except Exception:
            pass
    return True


def _apply_field_selection(rec, select_fields: Optional[str]) -> None:
    """Filters metadata fields to only requested field names."""
    if not select_fields:
        return
    names = {n.strip().lower() for n in select_fields.split(",") if n.strip()}
    rec.fields = [
        f for f in rec.fields
        if f.name.lower() in names or (f.tag_id and f.tag_id.lower() in names)
    ]


