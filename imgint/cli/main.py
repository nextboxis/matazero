"""Command-line interface for imgint per SRD §3.10 and SRS §3.1."""

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
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
import concurrent.futures

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

class DefaultGroup(click.Group):
    """Custom Click Group that defaults to a specified command (analyze) when invoked directly with image targets or options."""

    def __init__(self, *args, **kwargs):
        self.default_cmd_name = kwargs.pop("default", None)
        super().__init__(*args, **kwargs)

    def parse_args(self, ctx, args):
        if not args:
            return super().parse_args(ctx, args)
        if args[0] in ("-h", "--help", "--version"):
            return super().parse_args(ctx, args)
        if args[0] in self.commands:
            return super().parse_args(ctx, args)
        if self.default_cmd_name:
            args = [self.default_cmd_name] + list(args)
        return super().parse_args(ctx, args)

@click.group(cls=DefaultGroup, default="analyze")
@click.version_option(version=__version__, prog_name="matazero")
def cli() -> None:
    """matazero — Image Intelligence Toolkit for Ethical OSINT and Digital Forensics."""
    pass

from imgint.cli.commands import scope as scope_mod
from imgint.cli.commands import analyze as analyze_mod
from imgint.cli.commands import scan as scan_mod
from imgint.cli.commands import locate as locate_mod
from imgint.cli.commands import probe as probe_mod
from imgint.cli.commands import extract as extract_mod
from imgint.cli.commands import audit as audit_mod
from imgint.cli.commands import clean as clean_mod
from imgint.cli.commands import corpus as corpus_mod
from imgint.cli.commands import geo as geo_mod
from imgint.cli.commands import diff as diff_mod
from imgint.cli.commands import stego as stego_mod
from imgint.cli.commands import timeline as timeline_mod
from imgint.cli.commands import motion as motion_mod
from imgint.cli.commands import cluster as cluster_mod
from imgint.cli.commands import export as export_mod
from imgint.cli.commands import skill as skill_mod
from imgint.cli.commands import ask as ask_mod
from imgint.cli.commands import model as model_mod
from imgint.cli.commands import doctor as doctor_mod
from imgint.cli.commands import completion as completion_mod

cli.add_command(scope_mod.scope)
cli.add_command(analyze_mod.analyze)
cli.add_command(scan_mod.scan)
cli.add_command(locate_mod.locate)
cli.add_command(probe_mod.probe)
cli.add_command(extract_mod.extract)
cli.add_command(audit_mod.audit)
cli.add_command(clean_mod.clean)
cli.add_command(corpus_mod.corpus)
cli.add_command(geo_mod.geo_group, name="geo")
cli.add_command(diff_mod.diff)
cli.add_command(stego_mod.stego)
cli.add_command(timeline_mod.timeline)
cli.add_command(motion_mod.motion)
cli.add_command(cluster_mod.cluster)
cli.add_command(export_mod.export_group, name="export")
cli.add_command(skill_mod.skill_group, name="skill")
cli.add_command(ask_mod.ask)
cli.add_command(model_mod.model_group, name="model")
cli.add_command(doctor_mod.doctor)
cli.add_command(completion_mod.completion)

def main():
    try:
        cli()
    except Exception as e:
        err_console.print(f"[red]Fatal Error:[/red] {e}")
        sys.exit(ExitCode.ERROR_INTERNAL)

if __name__ == "__main__":
    main()
