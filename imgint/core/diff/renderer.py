"""Renderer for forensic differential analysis results."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from imgint.core.diff.comparator import ForensicDiffResult


class DiffRenderer:
    """Renders ForensicDiffResult as terminal Rich tables or structured JSON."""

    @classmethod
    def render_terminal(cls, result: ForensicDiffResult, console: Console) -> None:
        name_a = Path(result.target_a).name
        name_b = Path(result.target_b).name

        # Header Panel
        verdict_color = "green" if "EXACT" in result.relationship_verdict or "IDENTICAL" in result.relationship_verdict else "yellow" if "METADATA" in result.relationship_verdict or "RECOMPRESSION" in result.relationship_verdict else "bold red"
        
        panel_content = Text()
        panel_content.append(f"Image A (Reference): ", style="dim")
        panel_content.append(f"{name_a} ({result.size_a_bytes:,} B | {result.format_a})\n", style="bold cyan")
        panel_content.append(f"Image B (Target):    ", style="dim")
        panel_content.append(f"{name_b} ({result.size_b_bytes:,} B | {result.format_b})\n\n", style="bold cyan")
        panel_content.append(f"Forensic Verdict:    ", style="bold")
        panel_content.append(f"[{result.relationship_verdict}]\n", style=verdict_color)
        for r in result.summary_reasons:
            panel_content.append(f" • {r}\n", style="white")

        console.print(Panel(panel_content, title="[bold]matazero Forensic Image Diff[/bold]", border_style="cyan"))

        # Core Metrics Table
        metrics_table = Table(title="Integrity & Similarity Metrics", show_header=True)
        metrics_table.add_column("Comparative Layer", style="bold")
        metrics_table.add_column("Metric / Status", style="yellow")
        metrics_table.add_column("Forensic Interpretation", style="dim")

        # Hashes
        sha_s = "[green]MATCH (Identical)[/green]" if result.sha256_match else "[red]DIVERGENT[/red]"
        metrics_table.add_row("Full File SHA-256", sha_s, "Whole-file bitwise integrity")

        data_s = "[green]MATCH (Identical Streams)[/green]" if result.data_hash_match else "[yellow]DIVERGENT[/yellow]" if not result.sha256_match else "[green]MATCH[/green]"
        metrics_table.add_row("Pure Data SHA-256", data_s, "Image payload without metadata headers")

        # Perceptual Hashes
        if result.phash_distance is not None:
            phash_s = f"{result.phash_distance} bits"
            ph_interp = "Visually identical" if result.phash_distance == 0 else "Near match" if result.phash_distance <= 5 else "Different content"
            metrics_table.add_row("pHash Hamming Distance", phash_s, ph_interp)

        # DQT Quantization
        if result.dqt_similarity_pct is not None:
            dqt_s = f"{result.dqt_similarity_pct}% (Distance: {result.dqt_euclidean_distance})"
            dqt_interp = "Identical quantization tables" if result.dqt_similarity_pct == 100 else "Re-compressed or different encoder"
            metrics_table.add_row("JPEG DQT Similarity", dqt_s, dqt_interp)

        # Pixel Diff
        if result.pixel_diff:
            px = result.pixel_diff
            alt_s = f"{px.get('altered_pixels_count', 0):,} ({px.get('altered_pixels_pct', 0)}%)"
            ssim_s = f"SSIM: {px.get('estimated_ssim', 1.0)} | MSE: {px.get('mean_squared_error', 0)}"
            metrics_table.add_row("Altered Pixels", alt_s, ssim_s)

        console.print(metrics_table)
        console.print("")

        # Metadata Diff Table
        m_diff = result.metadata_diff
        total_meta_changes = len(m_diff.added) + len(m_diff.removed) + len(m_diff.modified)
        if total_meta_changes > 0:
            meta_table = Table(title=f"Metadata Differences ({total_meta_changes} Changes, {m_diff.identical_count} Unchanged)")
            meta_table.add_column("Status", justify="center")
            meta_table.add_column("Tag / Field Name", style="bold cyan")
            meta_table.add_column("Image A Value", style="red")
            meta_table.add_column("Image B Value", style="green")

            for item in m_diff.added:
                meta_table.add_row("[green]+ ADDED[/green]", item["field"], "-", str(item["value"])[:45])
            for item in m_diff.removed:
                meta_table.add_row("[red]- REMOVED[/red]", item["field"], str(item["value"])[:45], "-")
            for item in m_diff.modified:
                meta_table.add_row("[yellow]~ MODIFIED[/yellow]", item["field"], str(item["value_a"])[:35], str(item["value_b"])[:35])

            console.print(meta_table)
        else:
            console.print(f"[dim]Metadata tags: {m_diff.identical_count} identical tags across both files.[/dim]")

    @classmethod
    def render_json(cls, result: ForensicDiffResult) -> str:
        return json.dumps(result.to_dict(), indent=2)
