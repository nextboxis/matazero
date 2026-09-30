"""CLI command: matazero encrypt — Image Encryption & Scrambling."""

from __future__ import annotations
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from PIL import Image

from imgint.cli.commands._utils import resolve_scope, ExitCode
from imgint.core.crypto import (
    Mulberry32Cipher,
    AesImageCipher,
    ArnoldCatMapCipher,
)

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)


@click.command("encrypt")
@click.argument("target", type=click.Path(exists=True))
@click.option("-p", "--password", "password", required=True, help="Encryption password/passkey")
@click.option(
    "-m",
    "--method",
    "method",
    type=click.Choice(["mulberry32", "aes-256-gcm", "aes-256-cbc", "chaos"], case_sensitive=False),
    default="mulberry32",
    help="Encryption method or cipher algorithm",
)
@click.option("-o", "--out", "out_file", default=None, type=click.Path(), help="Output path for encrypted image")
@click.option("--container", "as_container", is_flag=True, help="Encrypt entire file as a tamper-evident forensic container (.enc)")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode without an external scope")
def encrypt(
    target: str,
    password: str,
    method: str,
    out_file: Optional[str],
    as_container: bool,
    scope_path: Optional[str],
    self_audit: bool,
) -> None:
    """Encrypt or Scramble an Image for Secure Evidence Transit."""
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)

    target_path = Path(target)
    effective_method = method.lower()

    if as_container or (effective_method in ["aes-256-gcm", "aes-256-cbc"] and out_file and out_file.endswith(".enc")):
        if not out_file:
            out_file = str(target_path.parent / f"encrypted-{target_path.stem}.enc")
        try:
            AesImageCipher.encrypt_file(target_path, out_file, password)
            console.print(Panel(f"[bold green]File successfully encrypted into forensic container:[/bold green] {out_file}", title="matazero Encrypt"))
            return
        except Exception as e:
            err_console.print(f"[bold red]Container encryption failed:[/bold red] {e}")
            sys.exit(ExitCode.GENERIC_ERROR)

    if not out_file:
        out_file = str(target_path.parent / f"encrypted-{target_path.stem}.png")

    try:
        import json
        from PIL.PngImagePlugin import PngInfo

        img = Image.open(target_path)
        pnginfo = PngInfo()

        if effective_method == "mulberry32":
            enc_img = Mulberry32Cipher.encrypt(img, password)
        elif effective_method == "chaos":
            enc_img = ArnoldCatMapCipher.encrypt(img)
        elif effective_method in ("aes-256-gcm", "aes-256-cbc"):
            aes_mode = "gcm" if "gcm" in effective_method else "cbc"
            enc_img, crypto_meta = AesImageCipher.encrypt_pixels(img, password, mode=aes_mode)
            pnginfo.add_text("matazero_crypto", json.dumps(crypto_meta))
        else:
            enc_img = Mulberry32Cipher.encrypt(img, password)

        enc_img.save(out_file, format="PNG", pnginfo=pnginfo)
    except Exception as e:
        err_console.print(f"[bold red]Encryption failed:[/bold red] {e}")
        sys.exit(ExitCode.GENERIC_ERROR)

    panel_text = Text()
    panel_text.append(f"Target Image:        ", style="dim")
    panel_text.append(f"{target_path.name} ({target_path.stat().st_size:,} bytes)\n", style="bold cyan")
    panel_text.append(f"Cipher Algorithm:    ", style="dim")
    panel_text.append(f"{effective_method.upper()}\n", style="white")
    panel_text.append(f"Passkey Configured:  ", style="dim")
    panel_text.append(f"'{password}'\n\n", style="bold yellow")
    panel_text.append(f"Encrypted Output:    ", style="dim")
    panel_text.append(f"{out_file}\n", style="bold green")

    console.print(Panel(panel_text, title="[bold]matazero Image Encryption Complete[/bold]", border_style="green"))
