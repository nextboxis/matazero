from __future__ import annotations

import json
import click
from rich.console import Console

from imgint.core.ai import OllamaClient, OllamaRenderer

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

@click.group("model")
def model_group() -> None:
    """Manage and inspect local vision models available in Ollama."""
    pass


@model_group.command("list")
@click.option("--host", default="http://localhost:11434", help="Ollama server host")
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
def model_list(host: str, out_fmt: str) -> None:
    """Discover and list installed models in local Ollama instance."""
    client = OllamaClient(host=host)
    is_online = client.is_available()
    models = client.list_models() if is_online else []

    if out_fmt == "json":
        print(json.dumps({
            "ollama_online": is_online,
            "host": host,
            "model_count": len(models),
            "models": models,
        }, indent=2))
    else:
        OllamaRenderer.render_models_table(models, is_online, console)
