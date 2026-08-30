"""Shared CLI utilities: scope resolution, target expansion, exit codes, and error formatting."""

from __future__ import annotations
import enum
import os
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from rich.console import Console
from rich.panel import Panel

from imgint.core.governance.scope import AuthorizationScope, ScopeValidationError


class ExitCode(enum.IntEnum):
    """Standardized process exit codes for matazero CLI."""
    SUCCESS = 0
    GENERIC_ERROR = 1
    USAGE_ERROR = 2
    FORMAT_ERROR = 3
    PARTIAL_FAILURE = 4
    SCOPE_ERROR = 6
    CUSTODY_ERROR = 7


def resolve_scope(
    scope_path: Optional[str],
    self_audit: bool,
    require_scope: bool = False,
    err_console: Optional[Console] = None,
) -> AuthorizationScope:
    """Resolve authorization scope from path or self-audit flag.
    
    Args:
        scope_path: Path to scope JSON file, or None.
        self_audit: If True and no scope_path, create self-audit scope.
        require_scope: If True, exit with SCOPE_ERROR when no scope is available.
        err_console: Console for error output.
    
    Returns:
        Resolved AuthorizationScope.
    
    Raises:
        SystemExit: If scope validation fails or scope is required but missing.
    """
    console = err_console or Console(stderr=True)
    
    if scope_path:
        try:
            return AuthorizationScope.load_from_file(scope_path)
        except ScopeValidationError as e:
            console.print(f"[bold red]Authorization failure (Exit {ExitCode.SCOPE_ERROR}): {e}[/bold red]")
            sys.exit(ExitCode.SCOPE_ERROR)
    
    if self_audit:
        return AuthorizationScope.create_self_audit_scope()
    
    if require_scope:
        console.print("[bold red]No authorization scope provided. Use --scope or --self-audit.[/bold red]")
        sys.exit(ExitCode.SCOPE_ERROR)
    
    return AuthorizationScope.create_self_audit_scope()


# Standard image file extensions for evidence discovery
IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp",
    ".heic", ".heif", ".avif", ".bmp", ".gif",
    ".docx", ".pptx",
}


def expand_targets(
    targets: Sequence[str],
    recursive: bool = False,
    glob_pattern: Optional[str] = None,
) -> List[Path]:
    """Expand file and directory targets into a flat list of evidence file paths.
    
    Args:
        targets: File paths or directory paths to expand.
        recursive: If True, recurse into subdirectories.
        glob_pattern: Optional glob filter (e.g. '*.jpg').
    
    Returns:
        Sorted, deduplicated list of resolved Path objects.
    """
    results: List[Path] = []
    seen: set = set()
    
    for t in targets:
        p = Path(t)
        if p.is_file():
            rp = p.resolve()
            if rp not in seen:
                seen.add(rp)
                results.append(rp)
        elif p.is_dir():
            pattern = glob_pattern or "*"
            iterator = p.rglob(pattern) if recursive else p.glob(pattern)
            for f in sorted(iterator):
                if f.is_file() and f.suffix.lower() in IMAGE_EXTENSIONS:
                    rf = f.resolve()
                    if rf not in seen:
                        seen.add(rf)
                        results.append(rf)
    
    return results


def format_error_panel(
    title: str,
    cause: str,
    suggestions: List[str],
    console: Console,
) -> None:
    """Display an actionable error panel with cause and suggested next steps."""
    lines = [f"[yellow]Cause: {cause}[/yellow]"]
    if suggestions:
        lines.append("[dim]Suggested Actions:[/dim]")
        for s in suggestions:
            lines.append(f"  [cyan]• {s}[/cyan]")
    console.print(Panel("\\n".join(lines), title=f"[bold red][!] {title}[/bold red]", border_style="red"))
