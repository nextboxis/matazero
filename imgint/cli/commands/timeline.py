from __future__ import annotations
import os
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console

from imgint.cli.commands._utils import resolve_scope, expand_targets
from imgint.core.pipeline import AnalysisPipeline
from imgint.core.timeline import TimelineReconstructor, TimelineExporter

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

@click.command("timeline")
@click.argument("targets", nargs=-1, required=True, type=click.Path())
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "json", "csv", "plaso"]), default="table", help="Output format")
@click.option("-o", "--out", "out_file", default=None, type=click.Path(), help="Write timeline to file")
@click.option("-r", "--recursive", is_flag=True, help="Recursively search directory targets for images")
@click.option("--glob", "glob_pattern", default=None, help="Glob pattern to filter files (e.g. '*.jpg')")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode without an external scope")
def timeline(
    targets: List[str],
    out_fmt: str,
    out_file: Optional[str],
    recursive: bool,
    glob_pattern: Optional[str],
    scope_path: Optional[str],
    self_audit: bool,
) -> None:
    """Reconstruct multi-asset chronological timelines and estimate camera clock drift."""
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)

    resolved_targets = expand_targets(targets, recursive=recursive, glob_pattern=glob_pattern)
    if not resolved_targets:
        err_console.print("[yellow]No matching image evidence files found to reconstruct timeline.[/yellow]")
        return

    pipeline = AnalysisPipeline(scope=auth_scope, selected_tiers={1, 5, 6})
    report = TimelineReconstructor.reconstruct(resolved_targets, pipeline=pipeline)

    if out_fmt == "json":
        rendered = TimelineExporter.to_json(report)
    elif out_fmt in ("csv", "plaso"):
        rendered = TimelineExporter.to_plaso_csv(report)
    else:
        TimelineExporter.render_terminal(report, console)
        rendered = ""

    if rendered:
        if out_file:
            Path(out_file).write_text(rendered, encoding="utf-8")
            console.print(f"[green][OK] Timeline written to {out_file}[/green]")
        else:
            print(rendered)
    elif out_file:
        Path(out_file).write_text(TimelineExporter.to_json(report), encoding="utf-8")
        console.print(f"\n[green][OK] Timeline data written to {out_file}[/green]")
