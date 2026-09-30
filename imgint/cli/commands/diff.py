from __future__ import annotations
import os
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from imgint.cli.commands._utils import resolve_scope
from imgint.core.pipeline import AnalysisPipeline
from imgint.core.diff import ForensicComparator, DiffRenderer

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
