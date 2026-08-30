"""Rich terminal and JSON renderer for Ollama Vision responses."""

from __future__ import annotations
import json
from typing import Any, Dict, List
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


class OllamaRenderer:
    """Renders Ollama Q&A responses and model tables with Rich formatting."""

    @classmethod
    def render_ask_response(
        cls, image_path: str | Path, question: str, model_name: str, response_text: str, console: Console
    ) -> None:
        file_name = Path(image_path).name

        panel_content = Text()
        panel_content.append("Evidence Target:  ", style="dim")
        panel_content.append(f"{file_name}\n", style="bold cyan")
        panel_content.append("Vision Model:     ", style="dim")
        panel_content.append(f"{model_name} (Local Ollama)\n", style="bold green")
        panel_content.append("Question Prompt:  ", style="dim")
        panel_content.append(f"{question}\n\n", style="bold yellow")
        panel_content.append("Visual Analysis:\n", style="bold underline white")
        panel_content.append(f"{response_text}\n", style="white")

        console.print(
            Panel(
                panel_content,
                title="[bold]matazero Local AI Visual Interrogation[/bold]",
                border_style="cyan",
            )
        )

    @classmethod
    def render_models_table(cls, models: List[Dict[str, Any]], is_online: bool, console: Console) -> None:
        if not is_online:
            console.print(
                Panel(
                    "[bold red][X] Ollama is currently offline or unreachable at http://localhost:11434[/bold red]\n\n"
                    "[dim]To start Ollama, run in your terminal:[/dim]\n"
                    "[bold green]ollama serve[/bold green]\n\n"
                    "[dim]To pull a local vision model, run:[/dim]\n"
                    "[bold cyan]ollama pull llama3.2-vision[/bold cyan] or [bold cyan]ollama pull moondream[/bold cyan]",
                    title="[bold]Ollama Local Vision Status[/bold]",
                    border_style="red",
                )
            )
            return

        if not models:
            console.print(
                Panel(
                    "[bold yellow]Ollama is online at http://localhost:11434, but no models are currently installed.[/bold yellow]\n\n"
                    "[dim]Pull a vision model to enable local AI features:[/dim]\n"
                    "[bold cyan]ollama pull llama3.2-vision[/bold cyan]\n"
                    "[bold cyan]ollama pull moondream[/bold cyan]",
                    title="[bold]Ollama Local Models[/bold]",
                    border_style="yellow",
                )
            )
            return

        table = Table(title=f"Installed Local Ollama Models ({len(models)} Found)", border_style="cyan")
        table.add_column("Model Name", style="bold cyan")
        table.add_column("Size", style="green")
        table.add_column("Format", style="dim")
        table.add_column("Vision Capable", justify="center")
        table.add_column("Modified", style="dim")

        vision_keywords = ("llava", "moondream", "vision", "minicpm-v", "qwen2-vl", "bakllava")

        for m in models:
            name = m.get("name", "")
            size_gb = m.get("size", 0) / (1024 * 1024 * 1024)
            size_str = f"{size_gb:.2f} GB" if size_gb >= 1.0 else f"{m.get('size', 0)/(1024*1024):.0f} MB"
            fmt = m.get("details", {}).get("format", "gguf")
            mod = m.get("modified_at", "")[:10]
            is_vision = any(k in name.lower() for k in vision_keywords)
            vis_badge = "[bold green]YES[/bold green]" if is_vision else "[dim]No (Text only)[/dim]"

            table.add_row(name, size_str, fmt, vis_badge, mod)

        console.print(table)
