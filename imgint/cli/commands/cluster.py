from __future__ import annotations
import os
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console

from imgint.cli.commands._utils import resolve_scope, expand_targets
from imgint.core.pipeline import AnalysisPipeline
from imgint.core.cluster import ClusterEngine, ClusterRenderer

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

@click.command("cluster")
@click.argument("targets", nargs=-1, required=True, type=click.Path())
@click.option("--by", "strategy", type=click.Choice(["camera", "dqt", "geo", "visual"]), default="camera", help="Clustering dimension (default: camera)")
@click.option("--radius", "geo_radius", default=5.0, type=float, help="Geospatial clustering radius in km (default: 5.0)")
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.option("-o", "--out", "out_file", default=None, type=click.Path(), help="Write clustering report to file")
@click.option("-r", "--recursive", is_flag=True, help="Recursively search directory targets for images")
@click.option("--glob", "glob_pattern", default=None, help="Glob pattern to filter files (e.g. '*.jpg')")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode without an external scope")
def cluster(
    targets: List[str],
    strategy: str,
    geo_radius: float,
    out_fmt: str,
    out_file: Optional[str],
    recursive: bool,
    glob_pattern: Optional[str],
    scope_path: Optional[str],
    self_audit: bool,
) -> None:
    """Group evidence files by camera fleet, DQT tables, GPS proximity, or visual similarity."""
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)

    resolved_targets = expand_targets(targets, recursive=recursive, glob_pattern=glob_pattern)
    if not resolved_targets:
        err_console.print("[yellow]No matching image evidence files found to cluster.[/yellow]")
        return

    pipeline = AnalysisPipeline(scope=auth_scope, selected_tiers={1, 2, 4, 5, 6})
    report = ClusterEngine.cluster(resolved_targets, strategy=strategy, geo_radius_km=geo_radius, pipeline=pipeline)

    if out_fmt == "json":
        rendered = ClusterRenderer.render_json(report)
        if out_file:
            Path(out_file).write_text(rendered, encoding="utf-8")
            console.print(f"[green][OK] Cluster data written to {out_file}[/green]")
        else:
            print(rendered)
    else:
        ClusterRenderer.render_terminal(report, console)
        if out_file:
            Path(out_file).write_text(ClusterRenderer.render_json(report), encoding="utf-8")
            console.print(f"\n[green][OK] Cluster data written to {out_file}[/green]")
