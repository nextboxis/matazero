from __future__ import annotations
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel

from imgint.cli.commands._utils import resolve_scope, ExitCode
from imgint.core.stego import StegoInspector, StegoRenderer, LsbStego, TrailingPayload

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

@click.command("stego")
@click.argument("target", type=click.Path(exists=True))
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
@click.option("-o", "--out", "out_file", default=None, type=click.Path(), help="Write analysis report or extracted/injected payload to file")
@click.option("--save-bitplanes", "save_bp_dir", default=None, type=click.Path(), help="Directory to save extracted bitplane PNG images")
@click.option("--extract", "do_extract", is_flag=True, help="Extract hidden steganographic message or payload from image")
@click.option("--inject", "inject_text", default=None, help="Text message to embed into image LSBs")
@click.option("-p", "--password", "password", default=None, help="Password for stego payload encryption/decryption")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode without an external scope")
def stego(
    target: str,
    out_fmt: str,
    out_file: Optional[str],
    save_bp_dir: Optional[str],
    do_extract: bool,
    inject_text: Optional[str],
    password: Optional[str],
    scope_path: Optional[str],
    self_audit: bool,
) -> None:
    """Deep Steganography Inspection, LSB/Trailing Payload Extraction & Injection."""
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)

    from imgint.core.stego import LsbStego, TrailingPayload

    # Handle Injection
    if inject_text:
        target_path = Path(target)
        dest = out_file or str(target_path.parent / f"stego-{target_path.stem}.png")
        try:
            embedded_bytes = LsbStego.inject(
                target_path, message=inject_text, output_path=dest, password=password
            )
            console.print(
                Panel(
                    f"[bold green]Message embedded successfully![/bold green]\n"
                    f"Embedded Size: [cyan]{embedded_bytes}[/cyan] bytes\n"
                    f"Encrypted: [yellow]{bool(password)}[/yellow]\n"
                    f"Carrier Saved To: [bold cyan]{dest}[/bold cyan]",
                    title="matazero Stego Injection",
                    border_style="green",
                )
            )
            return
        except Exception as e:
            err_console.print(f"[bold red]Stego injection failed:[/bold red] {e}")
            sys.exit(ExitCode.GENERIC_ERROR)

    # Handle Extraction
    if do_extract:
        target_path = Path(target)
        found_any = False

        # 1. Try LSB extraction
        try:
            lsb_data, lsb_meta = LsbStego.extract(target_path, password=password)
            if lsb_data:
                found_any = True
                text_content = lsb_meta.get("recovered_text")
                if text_content:
                    console.print(
                        Panel(
                            f"[bold green]Recovered Hidden LSB Message:[/bold green]\n\n"
                            f"[white]{text_content}[/white]\n\n"
                            f"[dim]Encrypted: {lsb_meta.get('is_encrypted')} | Bytes: {len(lsb_data)}[/dim]",
                            title="matazero LSB Payload Extraction",
                            border_style="green",
                        )
                    )
                else:
                    console.print(
                        Panel(
                            f"[bold green]Recovered Binary LSB Payload:[/bold green] {len(lsb_data)} bytes\n"
                            f"[dim]Encrypted: {lsb_meta.get('is_encrypted')}[/dim]",
                            title="matazero LSB Payload Extraction",
                            border_style="green",
                        )
                    )
                if out_file:
                    Path(out_file).write_bytes(lsb_data)
                    console.print(f"[green][OK] Extracted payload written to {out_file}[/green]")
        except Exception as e:
            err_console.print(f"[yellow][!] LSB extraction error:[/yellow] {e}")

        # 2. Try Trailing payload extraction
        try:
            tr_data, tr_meta = TrailingPayload.extract_and_decrypt(target_path, password=password)
            if tr_data and tr_meta.get("found"):
                found_any = True
                console.print(
                    Panel(
                        f"[bold green]Recovered Trailing Carrier Payload:[/bold green]\n"
                        f"Payload Type: [cyan]{tr_meta.get('payload_type')}[/cyan]\n"
                        f"Offset: [dim]{tr_meta.get('offset')}[/dim] | Length: [dim]{tr_meta.get('length')} bytes[/dim]\n"
                        f"Encrypted: [yellow]{tr_meta.get('is_encrypted')}[/yellow]",
                        title="matazero Trailing Data Extraction",
                        border_style="green",
                    )
                )
                if out_file:
                    dest = out_file if not Path(out_file).exists() else f"{out_file}.trailing"
                    Path(dest).write_bytes(tr_data)
                    console.print(f"[green][OK] Trailing payload written to {dest}[/green]")
        except Exception as e:
            err_console.print(f"[yellow][!] Trailing payload extraction error:[/yellow] {e}")

        if not found_any:
            console.print("[yellow][!] No embedded matazero LSB or trailing carrier payload detected.[/yellow]")
        return

    # Standard Stego Inspection
    result = StegoInspector.inspect(target, save_bitplanes_dir=save_bp_dir)

    if out_fmt == "json":
        rendered = StegoRenderer.render_json(result)
        if out_file:
            Path(out_file).write_text(rendered, encoding="utf-8")
            console.print(f"[green][OK] Stego report written to {out_file}[/green]")
        else:
            print(rendered)
    else:
        StegoRenderer.render_terminal(result, console)
        if out_file:
            rendered = StegoRenderer.render_json(result)
            Path(out_file).write_text(rendered, encoding="utf-8")
            console.print(f"\n[green][OK] Full stego data written to {out_file}[/green]")
