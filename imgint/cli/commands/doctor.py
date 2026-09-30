from __future__ import annotations

import click
from rich.console import Console

from imgint.core.diag import DiagnosticRunner

console = Console(highlight=False)

@click.command("doctor")
def doctor() -> None:
    """Run system health and diagnostic checks across all forensic engines."""
    DiagnosticRunner.run_all_checks(console)
