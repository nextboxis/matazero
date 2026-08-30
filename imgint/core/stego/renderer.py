"""Renderer for steganography inspection results."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from imgint.core.stego.inspector import StegoAnalysisResult


class StegoRenderer:
    """Renders StegoAnalysisResult as terminal Rich tables or structured JSON."""

    @classmethod
    def render_terminal(cls, result: StegoAnalysisResult, console: Console) -> None:
        file_name = Path(result.target_file).name

        # Header Panel
        v_color = "green" if result.risk_level == "LOW" else "yellow" if result.risk_level == "MEDIUM" else "bold red"
        panel_content = Text()
        panel_content.append(f"Target Evidence:  ", style="dim")
        panel_content.append(f"{file_name} ({result.file_size_bytes:,} bytes | {result.dimensions.get('width')}x{result.dimensions.get('height')})\n", style="bold cyan")
        panel_content.append(f"Stego Verdict:    ", style="bold")
        panel_content.append(f"[{result.stego_verdict}] ", style=v_color)
        panel_content.append(f"(Risk Score: {result.stego_risk_score:.2f} | Risk: {result.risk_level})\n", style="dim")
        panel_content.append(f"LSB Bit Density:  ", style="dim")
        panel_content.append(f"{result.lsb_bit_density:.4f} (Ideal natural variance: ~0.5000)\n\n", style="white")

        panel_content.append("Forensic Findings & Anomaly Indicators:\n", style="bold")
        for ind in result.indicators:
            panel_content.append(f" • {ind}\n", style="white")

        console.print(Panel(panel_content, title="[bold]matazero Deep Steganography & Bitplane Inspector[/bold]", border_style="cyan"))

        # Bitplane Entropy Grid Table
        bp_table = Table(title="Bitplane Slicing Entropy Grid (H: 0.00 to 1.00)", show_header=True)
        bp_table.add_column("Bitplane", style="bold cyan")
        bp_table.add_column("Description", style="dim")
        bp_table.add_column("Red Channel H", justify="right")
        bp_table.add_column("Green Channel H", justify="right")
        bp_table.add_column("Blue Channel H", justify="right")

        def _format_entropy(val: float) -> str:
            if val > 0.99:
                return f"[bold red]{val:.4f}[/bold red]"
            elif val > 0.90:
                return f"[yellow]{val:.4f}[/yellow]"
            elif val > 0.60:
                return f"[green]{val:.4f}[/green]"
            else:
                return f"[dim]{val:.4f}[/dim]"

        for p in range(7, -1, -1):
            p_key = f"plane_{p}"
            desc = "MSB (Most Significant Bit)" if p == 7 else "LSB (Least Significant Bit)" if p == 0 else f"Bit {p}"
            r_ent = result.bitplane_entropies.get("red", {}).get(p_key, {}).get("entropy", 0.0)
            g_ent = result.bitplane_entropies.get("green", {}).get(p_key, {}).get("entropy", 0.0)
            b_ent = result.bitplane_entropies.get("blue", {}).get(p_key, {}).get("entropy", 0.0)

            bp_table.add_row(
                f"Plane {p}",
                desc,
                _format_entropy(r_ent),
                _format_entropy(g_ent),
                _format_entropy(b_ent),
            )

        console.print(bp_table)
        console.print("")

        # Chi-Square PoV Table
        chi_table = Table(title="Chi-Square (PoV) Pair-of-Values Statistical Test", show_header=True)
        chi_table.add_column("Color Channel", style="bold")
        chi_table.add_column("Chi-Square Stat (χ²)", justify="right", style="cyan")
        chi_table.add_column("Degrees of Freedom", justify="right", style="dim")
        chi_table.add_column("LSB Pairing Anomaly", style="yellow")

        for ch in ["red", "green", "blue"]:
            st = result.chi_square_stats.get(ch, {})
            anomaly_str = "[bold red]ANOMALOUS (Uniform Pairs)[/bold red]" if st.get("uniform_lsb_pairing_suspected") else "[green]NORMAL (Natural Variance)[/green]"
            chi_table.add_row(
                ch.capitalize(),
                str(st.get("chi_square_stat", "-")),
                str(st.get("degrees_of_freedom", "-")),
                anomaly_str,
            )

        console.print(chi_table)

        if result.saved_bitplane_files:
            console.print(f"\n[green][OK] Exported {len(result.saved_bitplane_files)} bitplane slice images:[/green]")
            for f in result.saved_bitplane_files:
                console.print(f"  • {f}")

    @classmethod
    def render_json(cls, result: StegoAnalysisResult) -> str:
        return json.dumps(result.to_dict(), indent=2)
