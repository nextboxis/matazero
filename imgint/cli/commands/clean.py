from __future__ import annotations
from typing import Optional

import click
from rich.console import Console

from imgint.core.clean.cleaner import MetadataCleaner

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
