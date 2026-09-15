"""CLI command: matazero decrypt — Forensic Image Decryption & Password Recovery."""

from __future__ import annotations
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from PIL import Image
import numpy as np

from imgint.cli.commands._utils import resolve_scope, ExitCode
from imgint.core.crypto import (
    Mulberry32Cipher,
    AesImageCipher,
    ArnoldCatMapCipher,
    EncryptionDetector,
    DictionaryCracker,
    MATA_CONTAINER_MAGIC,
)

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)


@click.command("decrypt")
@click.argument("target", type=click.Path(exists=True))
@click.option("-p", "--password", "password", default=None, help="Decryption password/passkey")
@click.option("--seed", "seed_val", default=None, type=str, help="Direct 32-bit PRNG seed (decimal or hex e.g. 1260129352 or 0x4b1c0c48)")
@click.option(
    "-m",
    "--method",
    "method",
    type=click.Choice(["auto", "mulberry32", "aes-256-gcm", "aes-256-cbc", "chaos"], case_sensitive=False),
    default="auto",
    help="Decryption method or cipher algorithm",
)
@click.option("-o", "--out", "out_file", default=None, type=click.Path(), help="Output path for decrypted image")
@click.option("-w", "--wordlist", "wordlist", default=None, type=click.Path(exists=True), help="Wordlist for dictionary recovery")
@click.option("--brute-force", "brute_force", is_flag=True, help="Run automated dictionary/entropy recovery if password is unknown")
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode without an external scope")
def decrypt(
    target: str,
    password: Optional[str],
    seed_val: Optional[str],
    method: str,
    out_file: Optional[str],
    wordlist: Optional[str],
    brute_force: bool,
    scope_path: Optional[str],
    self_audit: bool,
) -> None:
    """Forensic Image Decryption, De-Scrambling, and Passkey Recovery."""
    auth_scope = resolve_scope(scope_path, self_audit, require_scope=False, err_console=err_console)

    target_path = Path(target)
    if not out_file:
        stem = target_path.stem.replace("encrypted-", "").replace("scrambled-", "")
        out_file = str(target_path.parent / f"decrypted-{stem}.png")

    det_res = EncryptionDetector.analyze_file(target_path)

    # Check for matazero cryptographic container
    raw_data = target_path.read_bytes()
    if raw_data.startswith(MATA_CONTAINER_MAGIC) or method == "aes-256-gcm" and not target_path.suffix.lower() in [".png", ".jpg", ".jpeg"]:
        if not password:
            err_console.print("[bold red]Error:[/bold red] Encrypted forensic container requires --password (-p).")
            sys.exit(ExitCode.USAGE_ERROR)
        try:
            AesImageCipher.decrypt_file(target_path, out_file, password)
            console.print(Panel(f"[bold green]Successfully decrypted container evidence to:[/bold green] {out_file}", title="matazero Decrypt"))
            return
        except Exception as e:
            err_console.print(f"[bold red]Decryption failed:[/bold red] {e}")
            sys.exit(ExitCode.GENERIC_ERROR)

    img = Image.open(target_path)
    effective_method = method.lower()
    if effective_method == "auto":
        effective_method = "mulberry32"

    used_password = password
    parsed_seed = None
    if seed_val:
        try:
            parsed_seed = int(seed_val, 16) if seed_val.lower().startswith("0x") else int(seed_val)
        except ValueError:
            err_console.print(f"[bold red]Error:[/bold red] Invalid --seed value: '{seed_val}'. Must be decimal or hex.")
            sys.exit(ExitCode.USAGE_ERROR)

    # Automated password recovery if password/seed missing or brute_force requested
    if (not password and parsed_seed is None or brute_force) and effective_method == "mulberry32":
        console.print("[cyan][*] Searching for valid decryption key using entropy-guided dictionary heuristics...[/cyan]")
        recovered = DictionaryCracker.crack(target_path, wordlist_path=wordlist)
        if recovered:
            cand_recovered, score = recovered
            if cand_recovered.startswith("seed:"):
                s_str = cand_recovered[5:]
                parsed_seed = int(s_str, 16) if s_str.lower().startswith("0x") else int(s_str)
                used_password = None
                console.print(f"[bold green][OK] PRNG Seed successfully recovered:[/bold green] [bold yellow]{parsed_seed} (0x{parsed_seed:08x})[/bold yellow] (Continuity score: {score:.2f})")
            else:
                used_password = cand_recovered
                console.print(f"[bold green][OK] Passkey successfully recovered:[/bold green] [bold yellow]'{used_password}'[/bold yellow] (Continuity score: {score:.2f})")
        else:
            if not password and parsed_seed is None:
                err_console.print("[bold red]Error:[/bold red] Password/seed not provided and dictionary recovery found no candidate. Provide password with -p, seed with --seed, or specify custom wordlist with -w.")
                sys.exit(ExitCode.USAGE_ERROR)
            else:
                console.print("[yellow][!] Dictionary recovery found no alternate candidates; proceeding with provided parameters.[/yellow]")

    try:
        if effective_method == "mulberry32":
            dec_img = Mulberry32Cipher.decrypt(img, key=used_password, seed=parsed_seed)
        elif effective_method == "chaos":
            dec_img = ArnoldCatMapCipher.decrypt(img)
        else:
            # Fallback to Mulberry32
            dec_img = Mulberry32Cipher.decrypt(img, key=used_password, seed=parsed_seed)

        dec_img.save(out_file, format="PNG")
    except Exception as e:
        err_console.print(f"[bold red]Decryption failed:[/bold red] {e}")
        sys.exit(ExitCode.GENERIC_ERROR)

    # Calculate post-decryption quality / continuity metrics
    dec_arr = np.array(dec_img.convert("RGB"))
    horiz_diff = np.abs(dec_arr.astype(np.int32)[:, 1:, :] - dec_arr.astype(np.int32)[:, :-1, :]).mean()
    vert_diff = np.abs(dec_arr.astype(np.int32)[1:, :, :] - dec_arr.astype(np.int32)[:-1, :, :]).mean()
    recovered_gradient = float((horiz_diff + vert_diff) / 2.0)

    is_clean = recovered_gradient < 35.0
    status_color = "bold green" if is_clean else "bold yellow"
    status_text = "NATURAL VISUAL EVIDENCE RECOVERED" if is_clean else "POSSIBLY NOISY / PARTIAL RECOVERY"

    panel_text = Text()
    panel_text.append(f"Target Evidence:     ", style="dim")
    panel_text.append(f"{target_path.name} ({target_path.stat().st_size:,} bytes | {img.size[0]}x{img.size[1]})\n", style="bold cyan")
    panel_text.append(f"Decryption Method:   ", style="dim")
    panel_text.append(f"{effective_method.upper()}\n", style="white")
    if used_password:
        panel_text.append(f"Passkey Used:        ", style="dim")
        panel_text.append(f"'{used_password}'\n", style="bold yellow")
    elif parsed_seed is not None:
        panel_text.append(f"PRNG Seed Used:      ", style="dim")
        panel_text.append(f"{parsed_seed} (0x{parsed_seed:08x})\n", style="bold yellow")
    panel_text.append(f"Spatial Gradient:    ", style="dim")
    panel_text.append(f"{recovered_gradient:.2f} / 85.33 ", style="cyan")
    panel_text.append(f"[{status_text}]\n\n", style=status_color)
    panel_text.append(f"Decrypted Image:     ", style="dim")
    panel_text.append(f"{out_file}\n", style="bold green")


    console.print(Panel(panel_text, title="[bold]matazero Forensic Decryption Report[/bold]", border_style="green" if is_clean else "yellow"))
