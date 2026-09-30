from __future__ import annotations
import sys

import click
from rich.console import Console

from imgint.cli.commands._utils import ExitCode
from imgint.core.governance.audit import verify_audit_chain

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

@click.group()
def audit() -> None:
    """Verify or export the tamper-evident audit log."""
    pass


@audit.command("verify")
@click.argument("audit_file", default="./audit.jsonl", type=click.Path(exists=True))
def audit_verify(audit_file: str) -> None:
    """Cryptographically verify the hash chain of an audit log (GR-2.7)."""
    is_valid, broken_idx, message = verify_audit_chain(audit_file)
    if is_valid:
        console.print(f"[green][OK] {message}[/green]")
    else:
        err_console.print(f"[bold red][X] AUDIT CHAIN COMPROMISED (Exit 7): {message}[/bold red]")
        sys.exit(ExitCode.CUSTODY_ERROR)
