from __future__ import annotations
import json
import os
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console

from imgint.cli.commands._utils import resolve_scope, expand_targets
from imgint.core.pipeline import AnalysisPipeline
from imgint.core.export import SqliteExporter, StixExporter

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

@click.group("export")
def export_group() -> None:
    """Export forensic findings to SQLite database or STIX 2.1 Threat Intel bundles."""
    pass


@export_group.command("sqlite")
@click.argument("targets", nargs=-1, required=True, type=click.Path())
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
    resolved_targets = expand_targets(targets, recursive=recursive, glob_pattern=glob_pattern)
    if not resolved_targets:
        err_console.print("[yellow]No matching image files to export.[/yellow]")
        return

    pipeline = AnalysisPipeline(scope=auth_scope, selected_tiers={1, 2, 3, 4, 5, 6, 7})
    records = [pipeline.analyze_file(t) for t in resolved_targets]
    out_db = SqliteExporter.export(records, db_path)
    console.print(f"[green][OK] Successfully indexed {len(records)} evidence images into SQLite database: [bold]{out_db}[/bold][/green]")


@export_group.command("stix")
@click.argument("targets", nargs=-1, required=True, type=click.Path())
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
    resolved_targets = expand_targets(targets, recursive=recursive, glob_pattern=glob_pattern)
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
